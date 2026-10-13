package exepatch

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileMD5 returns the hex md5 of path's current on-disk bytes.
func fileMD5(t *testing.T, path string) string {
	t.Helper()
	sum := md5.Sum(readDisk(t, path))
	return hex.EncodeToString(sum[:])
}

// writeApplyFixture writes data to <tempdir>/FantaTennis.exe with perm and
// returns the path.
func writeApplyFixture(t *testing.T, data []byte, perm fs.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "FantaTennis.exe")
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

// readDisk returns the current on-disk bytes of path, failing if unreadable.
func readDisk(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return data
}

// assertNoBackup fails if a `.bak` file exists next to path.
func assertNoBackup(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Errorf("%s.bak exists (err=%v), want no backup file", path, err)
	}
}

// applyURLFixture builds a PE32 image whose refill-URL site points at a URL
// C-string at the start of .rdata, followed by a guard byte and a zero gap
// of gapLen bytes. The .rdata vsize is caller-controlled so tests can cut
// the mapped region short. It returns the image bytes and the matching
// test Anchors.
func applyURLFixture(t *testing.T, url string, gapLen int, vsize uint32) ([]byte, Anchors) {
	t.Helper()
	return applyURLFixtureAt(t, exeFixtureURLSite, url, gapLen, vsize)
}

// applyURLFixtureAt is applyURLFixture for an arbitrary URL site offset:
// the site is planted inside .text raw data and every URL anchor in the
// returned Anchors points at it, so tests can Apply whichever URL setting
// ID they exercise. The string layout (url, NUL, guard, gap) is the same.
func applyURLFixtureAt(t *testing.T, site int, url string, gapLen int, vsize uint32) ([]byte, Anchors) {
	t.Helper()
	rdata := append([]byte(url), 0, 0x01)
	rdata = append(rdata, make([]byte, gapLen)...)
	data := buildPE32(t, customDllFixtureBase,
		testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
		testSection{name: ".rdata", vaddr: 0x2000, vsize: vsize, data: rdata},
	)
	a := Anchors{URLSite: site, RegisterSite: site, ResetPwSite: site}
	plantURLSite(t, data, site, url, customDllFixtureBase+0x2000)
	return data, a
}

// applyURLFixtureParts builds applyURLFixture and also returns the file
// offset of the URL string (the start of .rdata raw data).
func applyURLFixtureParts(t *testing.T, url string, gapLen int, vsize uint32) ([]byte, Anchors, uint32) {
	t.Helper()
	data, a := applyURLFixture(t, url, gapLen, vsize)
	p, err := parsePE32(data)
	if err != nil {
		t.Fatalf("parsePE32: %v", err)
	}
	return data, a, p.sectionByName(".rdata").rawptr
}

const (
	applyShortURL = "http://s.io/"                   // 12 bytes, fits the exeFixture slot
	applyTinyURL  = "http://x"                       // 8 bytes, shortest scheme-valid URL used by the tests
	applyLongURL  = "https://gamefaqs.gamespot.com/" // 30 bytes
	applySlotURL  = "http://a.io/"                   // 12-byte URL used by the relocation fixtures
)

func TestApplyRefillURLInPlace(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	p, _ := parsePE32(data)
	strOff := p.sectionByName(".rdata").rawptr
	oldPtr := binary.LittleEndian.Uint32(data[exeFixtureURLSite+3:])

	md5After, err := e.Apply(settingIDRefillURL, applyShortURL)
	if err != nil {
		t.Fatalf("Apply(%q): %v", applyShortURL, err)
	}

	disk := readDisk(t, path)
	if md5After != fileMD5(t, path) {
		t.Errorf("returned md5 = %s, want the on-disk md5 %s", md5After, fileMD5(t, path))
	}
	if got := disk[strOff : strOff+uint32(len(applyShortURL))]; !bytes.Equal(got, []byte(applyShortURL)) {
		t.Errorf("on-disk string at %#x = %q, want %q", strOff, got, applyShortURL)
	}
	if disk[strOff+uint32(len(applyShortURL))] != 0 {
		t.Errorf("byte after new string = %#x, want NUL", disk[strOff+uint32(len(applyShortURL))])
	}
	// Old tail zeroed through the old terminator's position (old len 16).
	for k := len(applyShortURL) + 1; k <= len(exeFixtureURL); k++ {
		if disk[strOff+uint32(k)] != 0 {
			t.Errorf("old tail byte %d at %#x = %#x, want 0", k, strOff+uint32(k), disk[strOff+uint32(k)])
		}
	}
	if got := disk[exeFixtureURLSite+1]; got != byte(len(applyShortURL)) {
		t.Errorf("length byte = %d, want %d", got, len(applyShortURL))
	}
	if got := binary.LittleEndian.Uint32(disk[exeFixtureURLSite+3:]); got != oldPtr {
		t.Errorf("pointer = %#x, want unchanged %#x", got, oldPtr)
	}
	if !bytes.Equal(disk, e.data) {
		t.Error("on-disk bytes differ from e.data after Apply")
	}
	settings := e.Settings()
	if s := settings[0]; s.Value != applyShortURL || !s.Editable {
		t.Errorf("Settings()[refillUrl] = {Value:%q Editable:%v}, want {%q true}", s.Value, s.Editable, applyShortURL)
	}
	// Backup of the pre-patch bytes was created before the write.
	if got := readDisk(t, path+".bak"); !bytes.Equal(got, data) {
		t.Error(".bak does not hold the pre-patch bytes")
	}
	if snaps := snapshotFiles(t, filepath.Dir(path), path); len(snaps) != 1 {
		t.Errorf("snapshot count = %d (%v), want exactly 1", len(snaps), snaps)
	}
}

// TestApplyRegisterURLInPlace covers the registerUrl pipeline on the
// in-place path: the new URL fits the slot's capacity, so only the string,
// the old tail and the length byte change; the pointer stays put.
func TestApplyRegisterURLInPlace(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	p, _ := parsePE32(data)
	// The register string sits right after the refill string's NUL.
	strOff := p.sectionByName(".rdata").rawptr + uint32(len(exeFixtureURL)+1)
	oldPtr := binary.LittleEndian.Uint32(data[exeFixtureRegisterSite+3:])

	md5After, err := e.Apply(settingIDRegisterURL, applyShortURL)
	if err != nil {
		t.Fatalf("Apply(%q): %v", applyShortURL, err)
	}

	disk := readDisk(t, path)
	if md5After != fileMD5(t, path) {
		t.Errorf("returned md5 = %s, want the on-disk md5 %s", md5After, fileMD5(t, path))
	}
	if got := disk[strOff : strOff+uint32(len(applyShortURL))]; !bytes.Equal(got, []byte(applyShortURL)) {
		t.Errorf("on-disk string at %#x = %q, want %q", strOff, got, applyShortURL)
	}
	if disk[strOff+uint32(len(applyShortURL))] != 0 {
		t.Errorf("byte after new string = %#x, want NUL", disk[strOff+uint32(len(applyShortURL))])
	}
	// Old tail zeroed through the old terminator's position.
	for k := len(applyShortURL) + 1; k <= len(exeFixtureRegisterURL); k++ {
		if disk[strOff+uint32(k)] != 0 {
			t.Errorf("old tail byte %d at %#x = %#x, want 0", k, strOff+uint32(k), disk[strOff+uint32(k)])
		}
	}
	if got := disk[exeFixtureRegisterSite+1]; got != byte(len(applyShortURL)) {
		t.Errorf("length byte = %d, want %d", got, len(applyShortURL))
	}
	if got := binary.LittleEndian.Uint32(disk[exeFixtureRegisterSite+3:]); got != oldPtr {
		t.Errorf("pointer = %#x, want unchanged %#x", got, oldPtr)
	}
	// The refill string at .rdata's start is untouched.
	rdataOff := p.sectionByName(".rdata").rawptr
	if got := disk[rdataOff : rdataOff+uint32(len(exeFixtureURL))]; !bytes.Equal(got, []byte(exeFixtureURL)) {
		t.Errorf("refill string = %q, want %q (untouched)", got, exeFixtureURL)
	}
	if !bytes.Equal(disk, e.data) {
		t.Error("on-disk bytes differ from e.data after Apply")
	}
	if s := findSetting(t, e.Settings(), settingIDRegisterURL); s.Value != applyShortURL || !s.Editable {
		t.Errorf("Settings()[registerUrl] = {Value:%q Editable:%v}, want {%q true}", s.Value, s.Editable, applyShortURL)
	}
	if got := readDisk(t, path+".bak"); !bytes.Equal(got, data) {
		t.Error(".bak does not hold the pre-patch bytes")
	}
	if snaps := snapshotFiles(t, filepath.Dir(path), path); len(snaps) != 1 {
		t.Errorf("snapshot count = %d (%v), want exactly 1", len(snaps), snaps)
	}
}

// TestApplyResetPwURLRelocates covers the resetPasswordUrl pipeline on the
// relocation path: the slot is full, so the new URL lands in the first
// usable zero-gap in .rdata and the site's pointer is repointed at it.
func TestApplyResetPwURLRelocates(t *testing.T) {
	resetSessionForTest()
	// Tiny slot: URL + NUL + a guard byte, so capacity == len(applySlotURL).
	data, a := applyURLFixtureAt(t, exeFixtureResetPwSite, applySlotURL, 200, 0x1000)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	p, err := parsePE32(data)
	if err != nil {
		t.Fatalf("parsePE32: %v", err)
	}
	strOff := p.sectionByName(".rdata").rawptr
	if target, reason := resolveURL(data, p, exeFixtureResetPwSite); target == nil || target.capacity != len(applySlotURL) {
		t.Fatalf("precondition: target=%+v reason=%q, want capacity %d", target, reason, len(applySlotURL))
	}

	if _, err := e.Apply(settingIDResetPwURL, applyLongURL); err != nil {
		t.Fatalf("Apply(%q): %v", applyLongURL, err)
	}

	disk := readDisk(t, path)
	// The gap starts after url(12) + NUL + guard: file offset strOff+14.
	gapOff := strOff + 14
	gapVA := customDllFixtureBase + 0x2000 + (gapOff - strOff)
	if got := binary.LittleEndian.Uint32(disk[exeFixtureResetPwSite+3:]); got != gapVA {
		t.Errorf("pointer = %#x, want gap VA %#x", got, gapVA)
	}
	if got := disk[exeFixtureResetPwSite+1]; got != byte(len(applyLongURL)) {
		t.Errorf("length byte = %d, want %d", got, len(applyLongURL))
	}
	if got := disk[gapOff : gapOff+uint32(len(applyLongURL))+1]; !bytes.Equal(got, append([]byte(applyLongURL), 0)) {
		t.Errorf("relocated bytes at %#x = %q, want %q + NUL", gapOff, got[:len(applyLongURL)], applyLongURL)
	}
	// The old string is zeroed (its NUL terminator boundary intact).
	if got := disk[strOff : strOff+uint32(len(applySlotURL))]; !bytes.Equal(got, make([]byte, len(applySlotURL))) {
		t.Errorf("old string at %#x = % x, want all zeros", strOff, got)
	}
	// Exactly one reference points at the new VA: the site itself.
	var needle [4]byte
	binary.LittleEndian.PutUint32(needle[:], gapVA)
	var hits []int
	for i := 0; i+4 <= len(disk); i++ {
		if bytes.Equal(disk[i:i+4], needle[:]) {
			hits = append(hits, i)
		}
	}
	if len(hits) != 1 || hits[0] != exeFixtureResetPwSite+3 {
		t.Errorf("pointers to %#x at %v, want exactly [%d]", gapVA, hits, exeFixtureResetPwSite+3)
	}
	if !bytes.Equal(disk, e.data) {
		t.Error("on-disk bytes differ from e.data after Apply")
	}
	if s := findSetting(t, e.Settings(), settingIDResetPwURL); s.Value != applyLongURL || !s.Editable {
		t.Errorf("Settings()[resetPasswordUrl] = {Value:%q Editable:%v}, want {%q true}", s.Value, s.Editable, applyLongURL)
	}
	if got := readDisk(t, path+".bak"); !bytes.Equal(got, data) {
		t.Error(".bak does not hold the pre-patch bytes")
	}
}

func TestApplyRefillURLInPlaceShorterNullPads(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	p, _ := parsePE32(data)
	strOff := p.sectionByName(".rdata").rawptr

	if _, err := e.Apply(settingIDRefillURL, applyTinyURL); err != nil {
		t.Fatalf("Apply(%q): %v", applyTinyURL, err)
	}

	disk := readDisk(t, path)
	if got := disk[strOff : strOff+uint32(len(applyTinyURL))+1]; !bytes.Equal(got, append([]byte(applyTinyURL), 0)) {
		t.Errorf("on-disk bytes at %#x = % x, want %q + NUL", strOff, got, applyTinyURL)
	}
	// The rest of the 15-char slot (through the old terminator at 16) is zero.
	for k := len(applyTinyURL) + 1; k <= len(exeFixtureURL); k++ {
		if disk[strOff+uint32(k)] != 0 {
			t.Errorf("pad byte %d at %#x = %#x, want 0", k, strOff+uint32(k), disk[strOff+uint32(k)])
		}
	}
	if got := disk[exeFixtureURLSite+1]; got != byte(len(applyTinyURL)) {
		t.Errorf("length byte = %d, want %d", got, len(applyTinyURL))
	}
}

func TestApplyRefillURLRelocatesWhenFull(t *testing.T) {
	resetSessionForTest()
	// Tiny slot: URL + NUL + a guard byte, so capacity == len(slotURL).
	data, a, strOff := applyURLFixtureParts(t, applySlotURL, 200, 0x1000)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	p, err := parsePE32(data)
	if err != nil {
		t.Fatalf("parsePE32: %v", err)
	}
	if target, reason := resolveURL(data, p, a.URLSite); target == nil || target.capacity != len(applySlotURL) {
		t.Fatalf("precondition: target=%+v reason=%q, want capacity %d", target, reason, len(applySlotURL))
	}

	if _, err := e.Apply(settingIDRefillURL, applyLongURL); err != nil {
		t.Fatalf("Apply(%q): %v", applyLongURL, err)
	}

	disk := readDisk(t, path)
	// The gap starts after url(12) + NUL + guard: file offset strOff+14.
	gapOff := strOff + 14
	gapVA := customDllFixtureBase + 0x2000 + (gapOff - strOff)
	if got := binary.LittleEndian.Uint32(disk[exeFixtureURLSite+3:]); got != gapVA {
		t.Errorf("pointer = %#x, want gap VA %#x", got, gapVA)
	}
	if got := disk[exeFixtureURLSite+1]; got != byte(len(applyLongURL)) {
		t.Errorf("length byte = %d, want %d", got, len(applyLongURL))
	}
	if got := disk[gapOff : gapOff+uint32(len(applyLongURL))+1]; !bytes.Equal(got, append([]byte(applyLongURL), 0)) {
		t.Errorf("relocated bytes at %#x = %q, want %q + NUL", gapOff, got[:len(applyLongURL)], applyLongURL)
	}
	// The old string is zeroed (its NUL terminator boundary intact).
	if got := disk[strOff : strOff+uint32(len(applySlotURL))]; !bytes.Equal(got, make([]byte, len(applySlotURL))) {
		t.Errorf("old string at %#x = % x, want all zeros", strOff, got)
	}
	// Exactly one reference points at the new VA: the site itself.
	var needle [4]byte
	binary.LittleEndian.PutUint32(needle[:], gapVA)
	var hits []int
	for i := 0; i+4 <= len(disk); i++ {
		if bytes.Equal(disk[i:i+4], needle[:]) {
			hits = append(hits, i)
		}
	}
	if len(hits) != 1 || hits[0] != exeFixtureURLSite+3 {
		t.Errorf("pointers to %#x at %v, want exactly [%d]", gapVA, hits, exeFixtureURLSite+3)
	}
	if !bytes.Equal(disk, e.data) {
		t.Error("on-disk bytes differ from e.data after Apply")
	}
	if s := e.Settings()[0]; s.Value != applyLongURL || !s.Editable {
		t.Errorf("Settings()[refillUrl] = {Value:%q Editable:%v}, want {%q true}", s.Value, s.Editable, applyLongURL)
	}
}

func TestApplyRefillURLRelocateSkipsBadGaps(t *testing.T) {
	// Geometry of the .rdata raw data built by badGapsFixture (url 12 +
	// NUL + guard at offsets 0..13): gapA = zeros at raw 14..53, guard at
	// 54, gapB = zeros at raw 55..94.
	const (
		gapARaw   = 14
		gapBRaw   = 55
		gapLen    = 40
		plantOff  = 0x210 // a free spot inside .text raw data for the plant
		beyondEnd = 60    // vsize that cuts the mapped region before gapB
	)
	gapAVA := uint32(customDllFixtureBase + 0x2000 + gapARaw)
	gapBVA := uint32(customDllFixtureBase + 0x2000 + gapBRaw)
	// badGapsFixture builds the two-gap image and plants a pointer to
	// plantVA at plantOff; passing gapAVA makes gapA's exact VA
	// referenced, passing gapAVA+2 references only its interior.
	badGapsFixture := func(t *testing.T, vsize uint32, plantVA uint32) ([]byte, Anchors, uint32) {
		t.Helper()
		rdata := append([]byte(applySlotURL), 0, 0x01)
		rdata = append(rdata, make([]byte, gapLen)...)
		rdata = append(rdata, 0x01)
		rdata = append(rdata, make([]byte, gapLen)...)
		data := buildPE32(t, customDllFixtureBase,
			testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
			testSection{name: ".rdata", vaddr: 0x2000, vsize: vsize, data: rdata},
		)
		a := Anchors{URLSite: exeFixtureURLSite}
		data[a.URLSite] = 0x6a
		data[a.URLSite+1] = byte(len(applySlotURL))
		data[a.URLSite+2] = 0x68
		binary.LittleEndian.PutUint32(data[a.URLSite+3:], customDllFixtureBase+0x2000)
		binary.LittleEndian.PutUint32(data[plantOff:], plantVA)
		p, err := parsePE32(data)
		if err != nil {
			t.Fatalf("parsePE32: %v", err)
		}
		return data, a, p.sectionByName(".rdata").rawptr
	}

	t.Run("pointed gap skipped, lands in good gap", func(t *testing.T) {
		resetSessionForTest()
		data, a, strOff := badGapsFixture(t, 0x1000, gapAVA)
		if len(findPointers(data, gapAVA)) == 0 {
			t.Fatal("fixture plant did not register")
		}
		path := writeApplyFixture(t, data, 0o644)
		e, err := OpenExe(path, a)
		if err != nil {
			t.Fatalf("OpenExe: %v", err)
		}

		if _, err := e.Apply(settingIDRefillURL, applyLongURL); err != nil {
			t.Fatalf("Apply(%q): %v", applyLongURL, err)
		}

		disk := readDisk(t, path)
		gapBOff := strOff + gapBRaw
		if got := binary.LittleEndian.Uint32(disk[exeFixtureURLSite+3:]); got != gapBVA {
			t.Errorf("pointer = %#x, want gapB VA %#x (pointed gapA must be skipped)", got, gapBVA)
		}
		if got := disk[gapBOff : gapBOff+uint32(len(applyLongURL))]; !bytes.Equal(got, []byte(applyLongURL)) {
			t.Errorf("bytes at gapB = %q, want %q", got, applyLongURL)
		}
		if got := disk[strOff+gapARaw : strOff+gapARaw+gapLen]; !bytes.Equal(got, make([]byte, gapLen)) {
			t.Error("gapA (pointed) was written to despite being referenced")
		}
	})

	// A pointer into a gap's INTERIOR (candVA+2, not candVA itself) must
	// also disqualify the gap: writing the string would overwrite the
	// referenced dword. The relocation has to fall through to gapB.
	t.Run("interior-pointer gap skipped, lands in good gap", func(t *testing.T) {
		resetSessionForTest()
		data, a, strOff := badGapsFixture(t, 0x1000, gapAVA+2)
		if len(findPointers(data, gapAVA+2)) == 0 {
			t.Fatal("fixture plant did not register")
		}
		path := writeApplyFixture(t, data, 0o644)
		e, err := OpenExe(path, a)
		if err != nil {
			t.Fatalf("OpenExe: %v", err)
		}

		if _, err := e.Apply(settingIDRefillURL, applyLongURL); err != nil {
			t.Fatalf("Apply(%q): %v", applyLongURL, err)
		}

		disk := readDisk(t, path)
		gapBOff := strOff + gapBRaw
		if got := binary.LittleEndian.Uint32(disk[exeFixtureURLSite+3:]); got != gapBVA {
			t.Errorf("pointer = %#x, want gapB VA %#x (interior-referenced gapA must be skipped)", got, gapBVA)
		}
		if got := disk[gapBOff : gapBOff+uint32(len(applyLongURL))]; !bytes.Equal(got, []byte(applyLongURL)) {
			t.Errorf("bytes at gapB = %q, want %q", got, applyLongURL)
		}
		if got := disk[strOff+gapARaw : strOff+gapARaw+gapLen]; !bytes.Equal(got, make([]byte, gapLen)) {
			t.Error("gapA (interior referenced) was written to despite being referenced")
		}
	})

	t.Run("beyond-vsize gap rejected, no room", func(t *testing.T) {
		resetSessionForTest()
		// vsize ends before gapB's candidate would fit: gapA is fully
		// mapped (14+31 <= 60) but gapB starts at 55 and needs 86.
		data, a, _ := badGapsFixture(t, beyondEnd, gapAVA)
		path := writeApplyFixture(t, data, 0o644)
		e, err := OpenExe(path, a)
		if err != nil {
			t.Fatalf("OpenExe: %v", err)
		}

		if _, err = e.Apply(settingIDRefillURL, applyLongURL); err == nil || !strings.Contains(err.Error(), "no room") {
			t.Fatalf("Apply(%q) error = %v, want containing %q", applyLongURL, err, "no room")
		}
		if disk := readDisk(t, path); !bytes.Equal(disk, data) {
			t.Error("on-disk bytes changed despite the failed relocation")
		}
		assertNoBackup(t, path)
	})
}

func TestApplyURLRejectsBadValues(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}

	tests := []struct {
		name  string
		value string
		want  string // substring the error must mention
	}{
		{"empty", "", "empty URL"},
		{"nul byte", "a\x00b", "NUL"},
		{"over hard limit", strings.Repeat("a", urlHardLimit+1), "127"},
		// A scheme-less value would write fine but read back as disabled
		// forever (resolveURL requires an "http" prefix), so it must be
		// rejected before anything is written.
		{"no scheme", "example.com", "must start with http"},
	}
	for _, id := range []string{settingIDRefillURL, settingIDRegisterURL, settingIDResetPwURL} {
		for _, tc := range tests {
			if _, err := e.Apply(id, tc.value); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Apply(%s, %q) error = %v, want containing %q", id, tc.value, err, tc.want)
			}
			if disk := readDisk(t, path); !bytes.Equal(disk, data) {
				t.Errorf("on-disk bytes changed after rejected value %q for %s", tc.value, id)
			}
			assertNoBackup(t, path)
		}
	}
}

func TestApplyRefillURLAbortsWhenSiteChangedOnDisk(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	// Sabotage the site on disk after OpenExe; Apply must re-read and refuse.
	sabotaged := bytes.Clone(data)
	for i := 0; i < 7; i++ {
		sabotaged[exeFixtureURLSite+i] = 0x90
	}
	if err := os.WriteFile(path, sabotaged, 0o644); err != nil {
		t.Fatalf("WriteFile(sabotage): %v", err)
	}

	_, err = e.Apply(settingIDRefillURL, applyShortURL)
	if !errors.Is(err, ErrNotEditable) {
		t.Errorf("Apply error = %v, want ErrNotEditable", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, sabotaged) {
		t.Error("on-disk bytes differ from the sabotaged state")
	}
	assertNoBackup(t, path)
}

func TestApplyRefillURLWriteFailureLeavesFileIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file modes are not enforced, chmod 0444 cannot force a write failure")
	}
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	// The file is read-only but its directory stays writable, so backup
	// creation succeeds and only the final write fails.
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	_, err = e.Apply(settingIDRefillURL, applyShortURL)
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Apply error = %v, want a permission error", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("on-disk bytes changed despite the failed write")
	}
	// The in-memory state was not advanced either.
	if s := e.Settings()[0]; s.Value != exeFixtureURL {
		t.Errorf("Settings()[refillUrl].Value = %q, want %q (unchanged after failed write)", s.Value, exeFixtureURL)
	}
}

func TestApplyCustomDllBothDirections(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	origSite := bytes.Clone(data[a.CustomDllSite : a.CustomDllSite+7])

	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	if s := findSetting(t, e.Settings(), settingIDCustomDll); s.Value != customDllValueEnabled {
		t.Fatalf("precondition: customDll = %q, want %q", s.Value, customDllValueEnabled)
	}

	md5Disabled, err := e.Apply(settingIDCustomDll, customDllValueDisabled)
	if err != nil {
		t.Fatalf("Apply(customDll, disabled): %v", err)
	}
	disk := readDisk(t, path)
	if md5Disabled != fileMD5(t, path) {
		t.Errorf("disabled md5 = %s, want the on-disk md5 %s", md5Disabled, fileMD5(t, path))
	}
	if !bytes.Equal(disk[a.CustomDllSite:a.CustomDllSite+7], a.CustomDllNops) {
		t.Errorf("site bytes = % x, want seven NOPs", disk[a.CustomDllSite:a.CustomDllSite+7])
	}
	if disk[a.CavePusha] != 0x60 || !bytes.Equal(disk[a.CaveAddEsp:a.CaveAddEsp+3], customDllAddEsp) {
		t.Error("code cave damaged by the disable patch")
	}
	if !bytes.Equal(disk, e.data) {
		t.Error("on-disk bytes differ from e.data after Apply")
	}
	if s := findSetting(t, e.Settings(), settingIDCustomDll); s.Value != customDllValueDisabled || !s.Editable {
		t.Errorf("Settings()[customDll] = {Value:%q Editable:%v}, want {%q true}", s.Value, s.Editable, customDllValueDisabled)
	}

	// Re-enable through a fresh handle, as a second program run would.
	e2, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	md5Enabled, err := e2.Apply(settingIDCustomDll, customDllValueEnabled)
	if err != nil {
		t.Fatalf("Apply(customDll, enabled): %v", err)
	}
	disk = readDisk(t, path)
	if md5Enabled != fileMD5(t, path) {
		t.Errorf("enabled md5 = %s, want the on-disk md5 %s", md5Enabled, fileMD5(t, path))
	}
	if !bytes.Equal(disk[a.CustomDllSite:a.CustomDllSite+7], origSite) {
		t.Errorf("site bytes = % x, want the original % x", disk[a.CustomDllSite:a.CustomDllSite+7], origSite)
	}
	if s := findSetting(t, e2.Settings(), settingIDCustomDll); s.Value != customDllValueEnabled {
		t.Errorf("Settings()[customDll].Value = %q, want %q", s.Value, customDllValueEnabled)
	}
	// The pristine backup still holds the never-patched original.
	if bak := readDisk(t, path+".bak"); !bytes.Equal(bak, data) {
		t.Error(".bak does not hold the pristine original")
	}
}

func TestApplyCustomDllRejectsUnknownValue(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}

	_, err = e.Apply(settingIDCustomDll, "maybe")
	if err == nil || !strings.Contains(err.Error(), "maybe") {
		t.Errorf("Apply(customDll, maybe) error = %v, want one mentioning the value", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("on-disk bytes changed after rejected value")
	}
	assertNoBackup(t, path)
}

func TestApplyUnknownSettingID(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}

	_, err = e.Apply("nope", "")
	if err == nil || !strings.Contains(err.Error(), "unknown setting") {
		t.Errorf("Apply(nope) error = %v, want one mentioning the unknown setting", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("on-disk bytes changed after unknown setting ID")
	}
	assertNoBackup(t, path)
}

func TestApplyNotEditableReturnsSentinel(t *testing.T) {
	resetSessionForTest()
	// .text is all zeros: no setting resolves in this build.
	data := buildPE32(t, customDllFixtureBase,
		testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
		testSection{name: ".rdata", vaddr: 0x2000, vsize: 0x1000, data: make([]byte, 64)},
	)
	path := writeApplyFixture(t, data, 0o644)
	_, a := exeFixture(t)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}

	for _, id := range []string{settingIDRefillURL, settingIDRegisterURL, settingIDResetPwURL, settingIDCustomDll} {
		value := applyShortURL
		if id == settingIDCustomDll {
			value = customDllValueDisabled
		}
		if _, err := e.Apply(id, value); !errors.Is(err, ErrNotEditable) {
			t.Errorf("Apply(%s) error = %v, want ErrNotEditable", id, err)
		}
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("on-disk bytes changed despite every setting being disabled")
	}
	assertNoBackup(t, path)
}

// TestApplyRegisterURLNotEditableWhenOnlyItsSiteIsBroken pins that the
// per-ID anchor matters: a damaged register site disables registerUrl
// (ErrNotEditable) while the refill site stays resolvable.
func TestApplyRegisterURLNotEditableWhenOnlyItsSiteIsBroken(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	// Sabotage only the register site on disk after OpenExe.
	sabotaged := bytes.Clone(data)
	for i := 0; i < 7; i++ {
		sabotaged[exeFixtureRegisterSite+i] = 0x90
	}
	if err := os.WriteFile(path, sabotaged, 0o644); err != nil {
		t.Fatalf("WriteFile(sabotage): %v", err)
	}

	if _, err := e.Apply(settingIDRegisterURL, applyShortURL); !errors.Is(err, ErrNotEditable) {
		t.Errorf("Apply(registerUrl) error = %v, want ErrNotEditable", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, sabotaged) {
		t.Error("on-disk bytes differ from the sabotaged state")
	}
	assertNoBackup(t, path)
	// Reopened against the sabotaged file, refill still resolves and only
	// registerUrl carries the disabled reason.
	e2, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	settings := e2.Settings()
	if s := findSetting(t, settings, settingIDRefillURL); !s.Editable || s.Value != exeFixtureURL {
		t.Errorf("refillUrl = {Editable:%v Value:%q}, want still editable with %q", s.Editable, s.Value, exeFixtureURL)
	}
	if s := findSetting(t, settings, settingIDRegisterURL); s.Editable || s.Reason == "" {
		t.Errorf("registerUrl = {Editable:%v Reason:%q}, want disabled with a reason", s.Editable, s.Reason)
	}
}

func TestApplyCustomDllCaveMismatchLeavesFileUnchanged(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	// Break the cave's add-esp trailer on disk after OpenExe.
	sabotaged := bytes.Clone(data)
	sabotaged[a.CaveAddEsp] = 0x90
	if err := os.WriteFile(path, sabotaged, 0o644); err != nil {
		t.Fatalf("WriteFile(sabotage): %v", err)
	}

	if _, err := e.Apply(settingIDCustomDll, customDllValueDisabled); !errors.Is(err, ErrNotEditable) {
		t.Errorf("Apply(customDll, disabled) error = %v, want ErrNotEditable (cave unrecognized)", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, sabotaged) {
		t.Error("on-disk bytes changed despite the cave mismatch")
	}
	assertNoBackup(t, path)
}

func TestApplyCustomDllRequiresKernel32(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	// Scrub the kernel32.dll sanity string; the customDll sites stay valid.
	idx := bytes.Index(data, []byte(sanityKernel32))
	if idx == -1 {
		t.Fatal("fixture is missing the kernel32.dll string")
	}
	copy(data[idx:], []byte("xxxxxxxxxxxx"))
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}

	_, err = e.Apply(settingIDCustomDll, customDllValueDisabled)
	if err == nil {
		t.Fatal("Apply(customDll, disabled) without kernel32.dll: error = nil, want a sanity failure")
	}
	if errors.Is(err, ErrNotEditable) {
		t.Errorf("Apply error = %v, want a plain sanity error, not ErrNotEditable", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("on-disk bytes changed despite the failed sanity check")
	}
	assertNoBackup(t, path)
}

func TestApplyIdempotentNoOp(t *testing.T) {
	resetSessionForTest()
	data, a := exeFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}

	// Re-applying the current values must succeed without touching anything,
	// returning the current file's md5.
	for _, tc := range []struct{ id, value string }{
		{settingIDRefillURL, exeFixtureURL},
		{settingIDRegisterURL, exeFixtureRegisterURL},
		{settingIDResetPwURL, exeFixtureResetPwURL},
		{settingIDCustomDll, customDllValueEnabled},
	} {
		md5Noop, err := e.Apply(tc.id, tc.value)
		if err != nil {
			t.Errorf("Apply(%s, current) = %v, want nil", tc.id, err)
			continue
		}
		if md5Noop != fileMD5(t, path) {
			t.Errorf("Apply(%s, current) md5 = %s, want the on-disk md5 %s", tc.id, md5Noop, fileMD5(t, path))
		}
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("on-disk bytes changed by a no-op Apply")
	}
	assertNoBackup(t, path)
	if snaps := snapshotFiles(t, filepath.Dir(path), path); len(snaps) != 0 {
		t.Errorf("snapshots created by a no-op Apply: %v", snaps)
	}

	// A no-op after a real change keeps the original backup intact.
	if _, err := e.Apply(settingIDCustomDll, customDllValueDisabled); err != nil {
		t.Fatalf("Apply(customDll, disabled): %v", err)
	}
	patched := readDisk(t, path)
	if _, err := e.Apply(settingIDCustomDll, customDllValueDisabled); err != nil {
		t.Errorf("second Apply(customDll, disabled) = %v, want nil", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, patched) {
		t.Error("on-disk bytes changed by a repeated identical Apply")
	}
	if bak := readDisk(t, path+".bak"); !bytes.Equal(bak, data) {
		t.Error(".bak does not hold the pristine original")
	}
}
