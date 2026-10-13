package exepatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

// Fixture geometry shared by the resolveCustomDll tests: the cave and the call
// site are planted inside .text raw data (file offsets 0x200..0x400) with
// the spacing of the real binary — pusha at 0x273, site at 0x280 (seven
// bytes), add-esp at 0x287 (13 bytes after pusha, 7 bytes after the site).
const (
	customDllFixtureBase   = 0x400000
	customDllFixturePusha  = 0x273
	customDllFixtureSite   = 0x280
	customDllFixtureAddEsp = 0x287
)

// customDllFixtureName is the dll name planted in every fixture cave.
const customDllFixtureName = "fanta.dll"

// plantNamePushes writes the three stack pushes that spell name inside the
// cave at file offset p: `6a <c>` (imm8), `68 <le32>` and `68 <le32>`
// (the string reads imm32 + imm32 + imm8, NUL-terminated by the imm8
// push's zero extension).
func plantNamePushes(t *testing.T, data []byte, p int, name string) {
	t.Helper()
	if len(name) > 9 {
		t.Fatalf("plantNamePushes: name %q longer than 9 bytes", name)
	}
	var w [9]byte
	copy(w[:], name)
	data[p+1] = 0x6a
	data[p+2] = w[8]
	data[p+3] = 0x68
	binary.LittleEndian.PutUint32(data[p+4:], uint32(w[4])|uint32(w[5])<<8|uint32(w[6])<<16|uint32(w[7])<<24)
	data[p+8] = 0x68
	binary.LittleEndian.PutUint32(data[p+9:], uint32(w[0])|uint32(w[1])<<8|uint32(w[2])<<16|uint32(w[3])<<24)
}

// plantCustomDll writes the cave (pusha, the name pushes, add-esp) and the
// original call-site bytes into data at the anchor offsets, which are file
// offsets that must fall inside .text raw data (0x200..0x400 of a fixture
// image).
func plantCustomDll(t *testing.T, data []byte, a Anchors) {
	t.Helper()
	if a.CavePusha < 0x200 || a.CustomDllSite < 0x200 || a.CaveAddEsp+2 >= 0x400 {
		t.Fatalf("plantCustomDll: anchors outside .text raw data: %+v", a)
	}
	data[a.CavePusha] = 0x60 // pusha
	plantNamePushes(t, data, a.CavePusha, customDllFixtureName)
	copy(data[a.CustomDllSite:], a.CustomDllOriginal)
	data[a.CaveAddEsp] = 0x83 // add esp, 0x0c
	data[a.CaveAddEsp+1] = 0xc4
	data[a.CaveAddEsp+2] = 0x0c
}

// customDllFixture builds a PE32 image with the code cave (pusha / add-esp) and
// the seven-byte customDll call site planted in .text raw data, plus the
// kernel32.dll sanity string in .rdata. It returns the image bytes and the
// matching test Anchors.
func customDllFixture(t *testing.T) ([]byte, Anchors) {
	t.Helper()
	a := Anchors{
		CustomDllSite:     customDllFixtureSite,
		CavePusha:         customDllFixturePusha,
		CaveAddEsp:        customDllFixtureAddEsp,
		CustomDllOriginal: []byte{0x54, 0xff, 0x15, 0xf8, 0x61, 0x6e, 0x00},
		CustomDllNops:     bytes.Repeat([]byte{0x90}, 7),
	}
	data := buildPE32(t, customDllFixtureBase,
		testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
		testSection{name: ".rdata", vaddr: 0x2000, vsize: 0x1000, data: append([]byte(sanityKernel32), 0)},
	)
	plantCustomDll(t, data, a)
	return data, a
}

func TestResolveCustomDllEnabled(t *testing.T) {
	data, a := customDllFixture(t)
	value, reason := resolveCustomDll(data, a)
	if value != "enabled" || reason != "" {
		t.Errorf("resolveCustomDll(original bytes) = (%q, %q), want (%q, %q)", value, reason, "enabled", "")
	}
}

func TestResolveCustomDllDisabled(t *testing.T) {
	data, a := customDllFixture(t)
	copy(data[customDllFixtureSite:], a.CustomDllNops)
	value, reason := resolveCustomDll(data, a)
	if value != "disabled" || reason != "" {
		t.Errorf("resolveCustomDll(seven NOPs) = (%q, %q), want (%q, %q)", value, reason, "disabled", "")
	}
}

func TestResolveCustomDllUnexpectedBytes(t *testing.T) {
	data, a := customDllFixture(t)
	copy(data[customDllFixtureSite:], []byte{0x55, 0x8b, 0xec, 0x83, 0xec, 0x10, 0x53})
	value, reason := resolveCustomDll(data, a)
	if value != "" || reason != "unexpected bytes at call site" {
		t.Errorf("resolveCustomDll(foreign site bytes) = (%q, %q), want (%q, %q)",
			value, reason, "", "unexpected bytes at call site")
	}
}

// TestResolveCustomDllBrokenCave pins the check order: the cave (pusha byte,
// add-esp bytes) is validated before the site bytes are compared, so a
// broken cave wins even when the site bytes are also unexpected.
func TestResolveCustomDllBrokenCave(t *testing.T) {
	siteSabotage := func(data []byte) {
		copy(data[customDllFixtureSite:], []byte{0x55, 0x8b, 0xec, 0x83, 0xec, 0x10, 0x53})
	}
	t.Run("pusha", func(t *testing.T) {
		data, a := customDllFixture(t)
		data[customDllFixturePusha] = 0x61 // not pusha
		siteSabotage(data)
		value, reason := resolveCustomDll(data, a)
		if value != "" || reason != "not the expected code cave" {
			t.Errorf("resolveCustomDll(broken pusha) = (%q, %q), want (%q, %q)",
				value, reason, "", "not the expected code cave")
		}
	})
	t.Run("add-esp", func(t *testing.T) {
		data, a := customDllFixture(t)
		data[customDllFixtureAddEsp] = 0x90 // not add esp, 0x0c
		siteSabotage(data)
		value, reason := resolveCustomDll(data, a)
		if value != "" || reason != "not the expected code cave" {
			t.Errorf("resolveCustomDll(broken add-esp) = (%q, %q), want (%q, %q)",
				value, reason, "", "not the expected code cave")
		}
	})
}

func TestResolveCustomDllShortFile(t *testing.T) {
	data, a := customDllFixture(t)
	// Ends before site+7 (and before CaveAddEsp+3): the bounds check fails,
	// which reports the cave reason.
	value, reason := resolveCustomDll(data[:customDllFixtureSite+3], a)
	if value != "" || reason != "not the expected code cave" {
		t.Errorf("resolveCustomDll(short file) = (%q, %q), want (%q, %q)",
			value, reason, "", "not the expected code cave")
	}
}

func TestCustomDllNameAtFixture(t *testing.T) {
	data, a := customDllFixture(t)
	name, ok := customDllNameAt(data, a.CavePusha)
	if !ok || name != customDllFixtureName {
		t.Errorf("customDllNameAt(fixture) = (%q, %v), want (%q, true)", name, ok, customDllFixtureName)
	}
}

// TestCustomDllNameAtLengths round-trips names of every interesting length
// through the push encoding: 9 chars fill the window with no stored NUL
// (the imm8 push's zero extension terminates at runtime), shorter names
// carry interior NULs.
func TestCustomDllNameAtLengths(t *testing.T) {
	for _, name := range []string{"a.dll", "ab.dll", "mod.dll", "fanta.dll"} {
		data := make([]byte, 64)
		plantNamePushes(t, data, 8, name)
		got, ok := customDllNameAt(data, 8)
		if !ok || got != name {
			t.Errorf("customDllNameAt(%q) = (%q, %v), want (%q, true)", name, got, ok, name)
		}
	}
}

func TestCustomDllNameAtRejects(t *testing.T) {
	cases := []struct {
		name string
		p    int
		mut  func(data []byte)
	}{
		{"all zeros", 8, func(d []byte) {
			// Opcodes stay; every name byte is zero (empty name).
			for _, i := range []int{10, 12, 13, 14, 15, 17, 18, 19, 20} {
				d[i] = 0
			}
		}},
		{"not push imm8", 8, func(d []byte) { d[9] = 0x60 }},
		{"first push not imm32", 8, func(d []byte) { d[11] = 0x6a }},
		{"second push not imm32", 8, func(d []byte) { d[16] = 0x6a }},
		{"garbage after NUL", 8, func(d []byte) {
			d[10] = 'm'
			d[13] = 0
			d[15] = 'x' // non-zero after the terminator inside the window
		}},
		{"space in name", 8, func(d []byte) { d[10] = ' ' }},
		{"short file", 8, func(d []byte) {}},
	}
	for _, tc := range cases {
		data := make([]byte, 64)
		plantNamePushes(t, data, 8, customDllFixtureName)
		tc.mut(data)
		end := len(data)
		if tc.name == "short file" {
			end = 8 + 9 // ends inside the window
		}
		if name, ok := customDllNameAt(data[:end], 8); ok {
			t.Errorf("customDllNameAt(%s) = (%q, true), want ok=false", tc.name, name)
		}
	}
}

func TestCustomDllName(t *testing.T) {
	resetSessionForTest()
	data, a := customDllFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	name, err := e.CustomDllName()
	if err != nil || name != customDllFixtureName {
		t.Errorf("CustomDllName() = (%q, %v), want (%q, nil)", name, err, customDllFixtureName)
	}

	// A broken cave reports the cave reason; unrecognizable name pushes
	// report the name reason.
	broken := bytes.Clone(data)
	broken[a.CavePusha] = 0x61
	assertCustomDllNameFails(t, path, broken, a, "code cave")

	noName := bytes.Clone(data)
	for i := a.CavePusha + 1; i <= a.CavePusha+12; i++ {
		noName[i] = 0
	}
	assertCustomDllNameFails(t, path, noName, a, "unrecognized dll name")
}

// assertCustomDllNameFails writes data over path, reopens it, and asserts
// CustomDllName fails with an error containing want.
func assertCustomDllNameFails(t *testing.T, path string, data []byte, a Anchors, want string) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := e.CustomDllName(); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("CustomDllName() error = %v, want one containing %q", err, want)
	}
}

func TestRenameCustomDll(t *testing.T) {
	resetSessionForTest()
	data, a := customDllFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}

	md5New, err := e.RenameCustomDll("patch.dll")
	if err != nil {
		t.Fatalf("RenameCustomDll(tennis.dll): %v", err)
	}
	if md5New != fileMD5(t, path) {
		t.Errorf("rename md5 = %s, want the on-disk md5 %s", md5New, fileMD5(t, path))
	}
	disk := readDisk(t, path)
	if got, ok := customDllNameAt(disk, a.CavePusha); !ok || got != "patch.dll" {
		t.Errorf("on-disk name = (%q, %v), want (tennis.dll, true)", got, ok)
	}
	// Only the name pushes changed: the call site, cave trailer and the
	// enabled state are untouched.
	if !bytes.Equal(disk[a.CustomDllSite:a.CustomDllSite+7], a.CustomDllOriginal) {
		t.Error("call site changed by the rename")
	}
	if !bytes.Equal(disk, e.data) {
		t.Error("on-disk bytes differ from e.data after RenameCustomDll")
	}
	if s := findSetting(t, e.Settings(), settingIDCustomDll); s.Value != customDllValueEnabled || !s.Editable {
		t.Errorf("Settings()[customDll] = {Value:%q Editable:%v}, want {%q true}", s.Value, s.Editable, customDllValueEnabled)
	}
	if name, err := e.CustomDllName(); err != nil || name != "patch.dll" {
		t.Errorf("CustomDllName() after rename = (%q, %v), want (tennis.dll, nil)", name, err)
	}
	// Backups follow the standard contract: pristine .bak + snapshot.
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("no pristine .bak after rename: %v", err)
	}
	if bak := readDisk(t, path+".bak"); !bytes.Equal(bak, data) {
		t.Error(".bak does not hold the pristine original")
	}

	// A shorter name round-trips too (interior NULs in the window).
	if _, err := e.RenameCustomDll("mod.dll"); err != nil {
		t.Fatalf("RenameCustomDll(mod.dll): %v", err)
	}
	if name, err := e.CustomDllName(); err != nil || name != "mod.dll" {
		t.Errorf("CustomDllName() after short rename = (%q, %v), want (mod.dll, nil)", name, err)
	}
}

// TestRenameCustomDllCasePreserved pins that an uppercase suffix is
// accepted (the loader matches case-insensitively) and written exactly
// as given.
func TestRenameCustomDllCasePreserved(t *testing.T) {
	resetSessionForTest()
	data, a := customDllFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	if _, err := e.RenameCustomDll("FANTA.DLL"); err != nil {
		t.Fatalf("RenameCustomDll(FANTA.DLL): %v", err)
	}
	if name, err := e.CustomDllName(); err != nil || name != "FANTA.DLL" {
		t.Errorf("CustomDllName() = (%q, %v), want (FANTA.DLL, nil)", name, err)
	}
}

func TestRenameCustomDllIdempotent(t *testing.T) {
	resetSessionForTest()
	data, a := customDllFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	md5Before := fileMD5(t, path)
	md5Same, err := e.RenameCustomDll(customDllFixtureName)
	if err != nil {
		t.Fatalf("RenameCustomDll(current name): %v", err)
	}
	if md5Same != md5Before {
		t.Errorf("no-op rename md5 = %s, want the unchanged file md5 %s", md5Same, md5Before)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("file bytes changed by a no-op rename")
	}
	assertNoBackup(t, path)
}

func TestRenameCustomDllRejectsInvalidNames(t *testing.T) {
	cases := []struct {
		name string // "" is exercised by the empty-string case below
		want string
	}{
		{"", "empty"},
		{".dll", "base name"},
		{"DLL", ".dll"},
		{"abcdefghij.dll", "exceeds"},
		{"tennis.dll.exe", "exceeds"},
		{"mod.exe", ".dll"},
		{".", ".dll"},
		{"te s.dll", "invalid character"},
		{"te\ns.dll", "invalid character"},
		{"te\x01s.dll", "invalid character"},
	}
	for _, tc := range cases {
		resetSessionForTest()
		data, a := customDllFixture(t)
		path := writeApplyFixture(t, data, 0o644)
		e, err := OpenExe(path, a)
		if err != nil {
			t.Fatalf("OpenExe: %v", err)
		}
		_, err = e.RenameCustomDll(tc.name)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("RenameCustomDll(%q) error = %v, want one containing %q", tc.name, err, tc.want)
		}
		if disk := readDisk(t, path); !bytes.Equal(disk, data) {
			t.Errorf("file bytes changed by rejected name %q", tc.name)
		}
		assertNoBackup(t, path)
	}
}

func TestRenameCustomDllRequiresKnownCurrentName(t *testing.T) {
	resetSessionForTest()
	data, a := customDllFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	for i := a.CavePusha + 1; i <= a.CavePusha+12; i++ {
		data[i] = 0
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	_, err = e.RenameCustomDll("mod.dll")
	if err == nil || !strings.Contains(err.Error(), "unrecognized dll name") {
		t.Errorf("RenameCustomDll with undecodable current name error = %v, want the name reason", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("file bytes changed despite the undecodable current name")
	}
	assertNoBackup(t, path)
}

func TestRenameCustomDllBrokenCave(t *testing.T) {
	resetSessionForTest()
	data, a := customDllFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	data[a.CavePusha] = 0x61
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	_, err = e.RenameCustomDll("mod.dll")
	if !errors.Is(err, ErrNotEditable) {
		t.Errorf("RenameCustomDll with broken cave error = %v, want ErrNotEditable", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("file bytes changed despite the broken cave")
	}
	assertNoBackup(t, path)
}

func TestRenameCustomDllRequiresKernel32(t *testing.T) {
	resetSessionForTest()
	data, a := customDllFixture(t)
	data = bytes.Replace(data, []byte(sanityKernel32), []byte("scRubb3d.dl"), 1)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	_, err = e.RenameCustomDll("mod.dll")
	if err == nil || !strings.Contains(err.Error(), "kernel32.dll") {
		t.Errorf("RenameCustomDll without kernel32.dll error = %v, want a sanity failure", err)
	}
	if disk := readDisk(t, path); !bytes.Equal(disk, data) {
		t.Error("file bytes changed despite the missing sanity string")
	}
	assertNoBackup(t, path)
}

func TestRenameCustomDllWhileDisabled(t *testing.T) {
	resetSessionForTest()
	data, a := customDllFixture(t)
	path := writeApplyFixture(t, data, 0o644)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	if _, err := e.Apply(settingIDCustomDll, customDllValueDisabled); err != nil {
		t.Fatalf("Apply(disabled): %v", err)
	}
	if _, err := e.RenameCustomDll("patch.dll"); err != nil {
		t.Fatalf("RenameCustomDll while disabled: %v", err)
	}
	if name, err := e.CustomDllName(); err != nil || name != "patch.dll" {
		t.Errorf("CustomDllName() = (%q, %v), want (tennis.dll, nil)", name, err)
	}
	if s := findSetting(t, e.Settings(), settingIDCustomDll); s.Value != customDllValueDisabled {
		t.Errorf("Settings()[customDll].Value = %q, want %q (still disabled)", s.Value, customDllValueDisabled)
	}
	// The toggle still works after the rename.
	if _, err := e.Apply(settingIDCustomDll, customDllValueEnabled); err != nil {
		t.Fatalf("Apply(enabled) after rename: %v", err)
	}
	if s := findSetting(t, e.Settings(), settingIDCustomDll); s.Value != customDllValueEnabled {
		t.Errorf("Settings()[customDll].Value = %q, want %q", s.Value, customDllValueEnabled)
	}
}
