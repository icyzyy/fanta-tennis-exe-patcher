package exepatch

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ErrNotEditable is returned by Apply when the requested setting does not
// resolve in the file: the setting's URL patch site is missing or
// unusable, or the customDll call site or code cave is not the expected one.
// The error wraps the resolver's reason.
var ErrNotEditable = errors.New("setting not editable")

// Apply sets the given setting to value and writes the result back to the
// file, returning the hex md5 of the written bytes. The file is re-read
// from disk first, so changes made since OpenExe are picked up; on success
// the receiver's in-memory state is updated to the written bytes, and
// Settings reports the new value. Validation failures, disabled settings,
// and failed verifications return before any backup or write. A value
// equal to the current one is a no-op success returning the current
// file's md5.
func (e *Exe) Apply(id, value string) (string, error) {
	switch id {
	case settingIDRefillURL:
		return e.applyURL(e.anchors.URLSite, value)
	case settingIDRegisterURL:
		return e.applyURL(e.anchors.RegisterSite, value)
	case settingIDResetPwURL:
		return e.applyURL(e.anchors.ResetPwSite, value)
	case settingIDCustomDll:
		return e.applyCustomDll(value)
	default:
		return "", fmt.Errorf("unknown setting %q", id)
	}
}

// md5Hex returns the hex-encoded md5 of data, matching the `md5:` line the
// CLI prints after a patch.
func md5Hex(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// reload re-reads the file from disk and re-parses it, so Apply always works
// against the on-disk state rather than a possibly stale snapshot.
func (e *Exe) reload() ([]byte, *peInfo, error) {
	data, err := os.ReadFile(e.path)
	if err != nil {
		return nil, nil, err
	}
	p, err := parsePE32(data)
	if err != nil {
		return nil, nil, err
	}
	return data, p, nil
}

// commit backs up the on-disk file, writes data over it with the original
// file mode (a direct whole-file write: a failure to open the file for
// writing — permissions, missing file — leaves it untouched, while a
// mid-write I/O failure such as a full disk can leave the target
// truncated, so recovery is via the .bak/snapshot written immediately
// beforehand), and advances the receiver's in-memory state to the
// written bytes. A backup failure aborts before the file is touched. On
// success it returns the hex md5 of the written bytes.
func (e *Exe) commit(data []byte, p *peInfo) (string, error) {
	if err := ensureBackups(e.path, time.Now()); err != nil {
		return "", err
	}
	info, err := os.Stat(e.path)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(e.path, data, info.Mode().Perm()); err != nil {
		return "", err
	}
	e.data = data
	e.pe = p
	return md5Hex(data), nil
}

// applyURL validates value, re-resolves the URL site at file offset site
// against the on-disk bytes, and rewrites the URL in place when it fits
// the slot's capacity or relocates it into the first usable zero-gap in
// .rdata. site is the per-ID anchor (URLSite / RegisterSite /
// ResetPwSite). On success it returns the hex md5 of the written bytes.
func (e *Exe) applyURL(site int, value string) (string, error) {
	switch {
	case value == "":
		return "", errors.New("empty URL")
	case strings.IndexByte(value, 0) != -1:
		return "", errors.New("URL contains a NUL byte")
	case len(value) > urlHardLimit:
		return "", fmt.Errorf("URL of %d bytes exceeds the %d-byte limit", len(value), urlHardLimit)
	case !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://"):
		// The reader (resolveURL) only accepts strings starting with
		// "http", so a scheme-less value would write fine but read back
		// as disabled forever.
		return "", errors.New("URL must start with http:// or https://")
	}
	data, p, err := e.reload()
	if err != nil {
		return "", err
	}
	target, reason := resolveURL(data, p, site)
	if target == nil {
		return "", fmt.Errorf("%w: %s", ErrNotEditable, reason)
	}
	if target.current == value {
		return md5Hex(data), nil // already the requested value
	}
	if len(value) <= target.capacity {
		urlApplyInPlace(data, target, value)
	} else if err := urlRelocate(data, p, target, value); err != nil {
		return "", err
	}
	if err := verifyURLPatch(data, p, site, value); err != nil {
		return "", fmt.Errorf("post-patch verification failed: %w", err)
	}
	return e.commit(data, p)
}

// urlApplyInPlace writes value over the current string, appends its NUL
// terminator, zeroes the old string's tail through the old terminator's
// position (matching the reference tool, which zeroes the old span), and
// updates the site's length byte. The pointer immediate is untouched.
func urlApplyInPlace(data []byte, target *urlTarget, value string) {
	copy(data[target.strOff:], value)
	data[target.strOff+uint32(len(value))] = 0
	for k := len(value) + 1; k <= len(target.current); k++ {
		data[target.strOff+uint32(k)] = 0
	}
	data[target.site+1] = byte(len(value))
}

// urlRelocate writes value plus its NUL terminator into the first zero-gap
// inside .rdata's raw data that is large enough, lies within the section's
// mapped virtual size, and is referenced by no pointer anywhere in the
// file — no little-endian uint32 anywhere may land in the gap's candidate
// span [gapVA, gapVA+len(value)+1), so pointers into the gap's interior
// disqualify it too; then it repoints the site's push immediate at the
// gap's VA, updates the length byte, and zeroes the old string (leaving
// its NUL terminator boundary intact, matching the reference tool). Every
// scan is clamped to the real file length.
func urlRelocate(data []byte, p *peInfo, target *urlTarget, value string) error {
	sec := p.sectionByName(".rdata")
	if sec == nil {
		return errors.New("no .rdata section") // OpenExe rejects these; keep the guard anyway
	}
	need := uint64(len(value)) + 1
	scanStart := uint64(sec.rawptr)
	scanEnd := min(uint64(sec.rawptr)+uint64(sec.rawsz), uint64(len(data)))
	for i := scanStart; i < scanEnd; {
		if data[i] != 0 {
			i++
			continue
		}
		j := i
		for j < scanEnd && data[j] == 0 {
			j++
		}
		runLen := j - i
		candRVA := uint64(sec.vaddr) + (i - scanStart)
		if runLen >= need && candRVA+need <= uint64(sec.vaddr)+uint64(sec.vsize) {
			candVA := p.imageBase + uint32(candRVA)
			// Conservative on span overflow (candVA+need past 2^32, only
			// reachable with a pathological image base): skip the gap
			// rather than leave the interior unchecked.
			spanHi := candVA + uint32(need)
			if spanHi >= candVA && len(findPointersInRange(data, candVA, spanHi)) == 0 {
				gapOff := uint32(i)
				copy(data[gapOff:], value)
				data[gapOff+uint32(len(value))] = 0
				data[target.site+1] = byte(len(value))
				binary.LittleEndian.PutUint32(data[target.site+3:], candVA)
				// Zero the old string; its NUL terminator boundary stays.
				for k := uint32(0); k < uint32(len(target.current)); k++ {
					data[target.strOff+k] = 0
				}
				return nil
			}
		}
		i = j
	}
	return fmt.Errorf("no room in .rdata: no zero-gap of at least %d bytes for the new URL", need)
}

// verifyURLPatch re-reads the patched data through the same machinery the
// resolvers use: the length byte at the per-setting site must match, the
// pointer must map back to a file offset holding exactly value as a
// C-string, and no other file location may hold that VA.
func verifyURLPatch(data []byte, p *peInfo, site int, value string) error {
	if site < 0 || len(data)-site < 7 {
		return errors.New("URL site out of bounds after patch")
	}
	if data[site] != 0x6a || data[site+2] != 0x68 {
		return errors.New("URL site shape damaged after patch")
	}
	if got := int(data[site+1]); got != len(value) {
		return fmt.Errorf("length byte = %d, want %d", got, len(value))
	}
	ptr := binary.LittleEndian.Uint32(data[site+3 : site+7])
	strOff, ok := p.vaToFile(ptr)
	if !ok {
		return fmt.Errorf("pointer %#x no longer maps to a file offset", ptr)
	}
	str, ok := cstringAt(data, strOff, 255)
	if !ok || str != value {
		return fmt.Errorf("readback %q, want %q", str, value)
	}
	if hits := findPointers(data, ptr); len(hits) != 1 || hits[0] != site+3 {
		return fmt.Errorf("pointer %#x referenced at file offsets %v, want only at the site (%d)", ptr, hits, site+3)
	}
	return nil
}

// applyCustomDll validates value, re-resolves the customDll state against the
// on-disk bytes, sanity-checks the file, verifies the code cave, and writes
// the original call bytes (enabled) or the NOP run (disabled). On success
// it returns the hex md5 of the written bytes.
func (e *Exe) applyCustomDll(value string) (string, error) {
	if value != customDllValueEnabled && value != customDllValueDisabled {
		return "", fmt.Errorf("invalid customDll value %q, want %q or %q", value, customDllValueEnabled, customDllValueDisabled)
	}
	data, p, err := e.reload()
	if err != nil {
		return "", err
	}
	current, reason := resolveCustomDll(data, e.anchors)
	if reason != "" {
		return "", fmt.Errorf("%w: %s", ErrNotEditable, reason)
	}
	if current == value {
		return md5Hex(data), nil // already the requested value
	}
	if !bytes.Contains(data, []byte(sanityKernel32)) {
		return "", errors.New("kernel32.dll sanity string missing: refusing to patch (wrong file?)")
	}
	a := e.anchors
	want := a.CustomDllOriginal
	if value == customDllValueDisabled {
		want = a.CustomDllNops
	}
	if len(want) != customDllSiteLen {
		return "", fmt.Errorf("anchor bytes for %q are %d bytes, want %d", value, len(want), customDllSiteLen)
	}
	// The cave must still be intact on the working copy before the site is
	// touched, mirroring the reference tool's verify-before-write.
	if a.CavePusha < 0 || a.CavePusha >= len(data) ||
		a.CaveAddEsp < 0 || a.CaveAddEsp+len(customDllAddEsp) > len(data) ||
		a.CustomDllSite < 0 || a.CustomDllSite+customDllSiteLen > len(data) {
		return "", fmt.Errorf("%w: %s", ErrNotEditable, reasonCustomDllCave)
	}
	if data[a.CavePusha] != 0x60 || !bytes.Equal(data[a.CaveAddEsp:a.CaveAddEsp+len(customDllAddEsp)], customDllAddEsp) {
		return "", fmt.Errorf("%w: %s", ErrNotEditable, reasonCustomDllCave)
	}
	copy(data[a.CustomDllSite:], want)
	// Post-mutation verification: site written, cave and sanity intact.
	if !bytes.Equal(data[a.CustomDllSite:a.CustomDllSite+customDllSiteLen], want) {
		return "", errors.New("customDll site verification failed")
	}
	if data[a.CavePusha] != 0x60 || !bytes.Equal(data[a.CaveAddEsp:a.CaveAddEsp+len(customDllAddEsp)], customDllAddEsp) {
		return "", errors.New("customDll code cave damaged by patch")
	}
	if !bytes.Contains(data, []byte(sanityKernel32)) {
		return "", errors.New("kernel32.dll sanity string lost during patch")
	}
	return e.commit(data, p)
}

// findPointers returns every file offset at which a little-endian uint32
// equal to va occurs. The scan never reads past the end of data.
func findPointers(data []byte, va uint32) []int {
	var needle [4]byte
	binary.LittleEndian.PutUint32(needle[:], va)
	var hits []int
	for i := 0; i+4 <= len(data); i++ {
		if bytes.Equal(data[i:i+4], needle[:]) {
			hits = append(hits, i)
		}
	}
	return hits
}

// findPointersInRange returns every file offset at which a little-endian
// uint32 falls in the closed-open span [lo, hi) — a single pass with a
// range comparison, the same cost as findPointers. It guards gap
// candidates during relocation: not only a pointer to the gap's first byte
// but any pointer into the gap's interior disqualifies it, because writing
// the string would overwrite the referenced dword. An empty span (hi <=
// lo) has no hits. The scan never reads past the end of data.
func findPointersInRange(data []byte, lo, hi uint32) []int {
	if hi <= lo {
		return nil
	}
	var hits []int
	for i := 0; i+4 <= len(data); i++ {
		if v := binary.LittleEndian.Uint32(data[i : i+4]); v >= lo && v < hi {
			hits = append(hits, i)
		}
	}
	return hits
}
