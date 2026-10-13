package exepatch

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// the custom dll load values and the reasons the setting is disabled.
const (
	customDllValueEnabled  = "enabled"
	customDllValueDisabled = "disabled"

	reasonCustomDllCave = "not the expected code cave"
	reasonCustomDllSite = "unexpected bytes at call site"
	reasonCustomDllName = "unrecognized dll name in code cave"
)

// customDllSiteLen is the length of the call-site operand the patch rewrites:
// seven bytes at CustomDllSite.
const customDllSiteLen = 7

// customDllAddEsp are the three bytes that must trail the code cave at
// CaveAddEsp: `83 c4 0c` (add esp, 0x0c).
var customDllAddEsp = []byte{0x83, 0xc4, 0x0c}

// resolveCustomDll reports the state of the custom dll load patch in data,
// whose anchors are file offsets. Order: bounds (the file must cover the
// cave's add-esp operand and the call-site bytes), then the cave check
// (pusha 0x60 at CavePusha, add esp 0x0c at CaveAddEsp), then the site
// bytes — the original instruction means "enabled", the anchors' NOP run
// means "disabled", anything else is unmatched. On success it returns the
// value with an empty reason; on failure it returns ("", reason) saying
// why the setting is disabled in this build.
func resolveCustomDll(data []byte, a Anchors) (value string, reason string) {
	if a.CavePusha < 0 || a.CaveAddEsp < 0 || a.CustomDllSite < 0 ||
		a.CaveAddEsp+len(customDllAddEsp) > len(data) || a.CavePusha >= len(data) ||
		a.CustomDllSite+customDllSiteLen > len(data) {
		return "", reasonCustomDllCave
	}
	if data[a.CavePusha] != 0x60 ||
		!bytes.Equal(data[a.CaveAddEsp:a.CaveAddEsp+len(customDllAddEsp)], customDllAddEsp) {
		return "", reasonCustomDllCave
	}
	site := data[a.CustomDllSite : a.CustomDllSite+customDllSiteLen]
	switch {
	case bytes.Equal(site, a.CustomDllOriginal):
		return customDllValueEnabled, ""
	case bytes.Equal(site, a.CustomDllNops):
		return customDllValueDisabled, ""
	default:
		return "", reasonCustomDllSite
	}
}

// customDllNameMax is the longest dll name the cave's push encoding can
// spell: four characters per imm32 push plus one for the imm8 push. The
// name's NUL terminator comes from the imm8 push's zero extension, so a
// full-length name has no stored terminator at all.
const customDllNameMax = 9

// customDllNameChars are the bytes a dll name may contain: letters,
// digits, dot, underscore and hyphen.
const customDllNameChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"

// customDllNameCharOK reports whether b may appear in a dll name.
func customDllNameCharOK(b byte) bool {
	return strings.IndexByte(customDllNameChars, b) != -1
}

// customDllNameAt decodes the dll name spelled by the three stack pushes
// in the code cave at file offset cavePusha: `6a <c>` (push imm8) at
// +1, `68 <le32>` at +3 and `68 <le32>` at +8. The string at ESP reads
// the imm32 at +9, then the imm32 at +4, then the imm8 char at +2, so
// the decoded name is those nine bytes up to the first NUL. A name
// shorter than nine characters stores interior NULs, which must run to
// the end of the window; a full-length name is terminated only at
// runtime by the imm8 push's zero extension. It returns ("", false)
// when the opcodes are not the three pushes, the window is out of
// bounds, the name is empty or contains a byte outside
// customDllNameChars.
func customDllNameAt(data []byte, cavePusha int) (string, bool) {
	if cavePusha < 0 || cavePusha+13 > len(data) {
		return "", false
	}
	if data[cavePusha+1] != 0x6a || data[cavePusha+3] != 0x68 || data[cavePusha+8] != 0x68 {
		return "", false
	}
	var w [customDllNameMax]byte
	copy(w[0:4], data[cavePusha+9:cavePusha+13])
	copy(w[4:8], data[cavePusha+4:cavePusha+8])
	w[8] = data[cavePusha+2]
	end := customDllNameMax
	if nul := bytes.IndexByte(w[:], 0); nul >= 0 {
		for _, b := range w[nul:] {
			if b != 0 {
				return "", false // non-zero tail after the terminator
			}
		}
		end = nul
	}
	if end == 0 {
		return "", false
	}
	for _, c := range w[:end] {
		if !customDllNameCharOK(c) {
			return "", false
		}
	}
	return string(w[:end]), true
}

// CustomDllName returns the dll file name the code cave spells for the
// custom dll load: the cave must be the expected one (its reason is
// wrapped on failure) and its name pushes must decode (reasonCustomDllName
// otherwise).
func (e *Exe) CustomDllName() (string, error) {
	if _, reason := resolveCustomDll(e.data, e.anchors); reason != "" {
		return "", fmt.Errorf("custom dll: %s", reason)
	}
	name, ok := customDllNameAt(e.data, e.anchors.CavePusha)
	if !ok {
		return "", errors.New("custom dll: " + reasonCustomDllName)
	}
	return name, nil
}

// putCustomDllName writes name into the cave's name pushes starting at
// file offset cavePusha: `6a <c>` at +1, `68 <le32>` at +3 and
// `68 <le32>` at +8. name must be at most customDllNameMax bytes; the
// window is NUL-padded, so the encoded C-string ends right after the
// name. It is the inverse of customDllNameAt.
func putCustomDllName(data []byte, cavePusha int, name string) {
	var w [customDllNameMax]byte
	copy(w[:], name)
	data[cavePusha+1] = 0x6a
	data[cavePusha+2] = w[8]
	data[cavePusha+3] = 0x68
	copy(data[cavePusha+4:], w[4:8])
	data[cavePusha+8] = 0x68
	copy(data[cavePusha+9:], w[0:4])
}

// validateCustomDllName rejects names the cave encoding cannot spell or
// that the loader should not see: non-empty, at most customDllNameMax
// bytes of customDllNameChars, a non-empty base name, and a ".dll"
// suffix (compared case-insensitively — LoadLibraryA matches file names
// case-insensitively; the name is written exactly as given).
func validateCustomDllName(name string) error {
	if name == "" {
		return errors.New("empty dll name")
	}
	if len(name) > customDllNameMax {
		return fmt.Errorf("dll name %q of %d bytes exceeds the %d-byte limit", name, len(name), customDllNameMax)
	}
	for i := 0; i < len(name); i++ {
		if !customDllNameCharOK(name[i]) {
			return fmt.Errorf("dll name %q contains an invalid character %q", name, string(name[i]))
		}
	}
	if !strings.HasSuffix(strings.ToLower(name), ".dll") {
		return fmt.Errorf("dll name %q must end in .dll", name)
	}
	if strings.TrimSuffix(strings.ToLower(name), ".dll") == "" {
		return fmt.Errorf("dll name %q must contain a base name before .dll", name)
	}
	return nil
}

// RenameCustomDll rewrites the dll name the code cave spells, returning
// the hex md5 of the written bytes. The new name is validated first,
// then the on-disk bytes are re-resolved: the call site and cave must be
// the expected ones and the current name must decode, and renaming to
// the current name is a no-op success. The name pushes are rewritten
// through putCustomDllName and the readback, cave and kernel32.dll
// sanity string re-checked before the file is committed. Validation
// failures, an unresolvable cave or an undecodable current name return
// before any backup or write.
func (e *Exe) RenameCustomDll(name string) (string, error) {
	if err := validateCustomDllName(name); err != nil {
		return "", err
	}
	data, p, err := e.reload()
	if err != nil {
		return "", err
	}
	a := e.anchors
	if _, reason := resolveCustomDll(data, a); reason != "" {
		return "", fmt.Errorf("%w: %s", ErrNotEditable, reason)
	}
	// The name pushes occupy the 12 bytes between the pusha and the call
	// site in the real layout; refuse to write over either neighbor.
	if a.CavePusha+13 > a.CustomDllSite || a.CavePusha+13 > a.CaveAddEsp {
		return "", fmt.Errorf("%w: %s", ErrNotEditable, reasonCustomDllCave)
	}
	current, ok := customDllNameAt(data, a.CavePusha)
	if !ok {
		return "", errors.New("cannot rename: " + reasonCustomDllName)
	}
	if current == name {
		return md5Hex(data), nil // already the requested name
	}
	if !bytes.Contains(data, []byte(sanityKernel32)) {
		return "", errors.New("kernel32.dll sanity string missing: refusing to patch (wrong file?)")
	}
	putCustomDllName(data, a.CavePusha, name)
	// Post-mutation verification: readback, cave and sanity intact.
	if got, ok := customDllNameAt(data, a.CavePusha); !ok || got != name {
		return "", errors.New("custom dll name verification failed")
	}
	if data[a.CavePusha] != 0x60 || !bytes.Equal(data[a.CaveAddEsp:a.CaveAddEsp+len(customDllAddEsp)], customDllAddEsp) {
		return "", errors.New("custom dll code cave damaged by patch")
	}
	if !bytes.Contains(data, []byte(sanityKernel32)) {
		return "", errors.New("kernel32.dll sanity string lost during patch")
	}
	return e.commit(data, p)
}
