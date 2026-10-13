package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// section describes one section header plus its raw data for a fixture
// PE32 image.
type section struct {
	name  string
	vaddr uint32
	vsize uint32
	data  []byte
}

// Layout constants of the fixture images produced by buildPE32; a minimal
// duplicate of the exepatch test builder's geometry (the plan mandates a
// duplicated builder here rather than exporting anything from exepatch).
const (
	peELFanew     = 0x40
	peOptOff      = peELFanew + 4 + 20
	peFileAlign   = 0x200
	peSectionHdrs = 40
	peSizeOfOpt   = 0xE0
)

// alignUp rounds v up to the next multiple of align (a power of two).
func alignUp(v, align uint32) uint32 {
	return (v + align - 1) &^ (align - 1)
}

// buildPE32 builds a minimal in-memory PE32 image: a 64-byte DOS stub (MZ
// signature, e_lfanew=0x40), the PE\0\0 signature, a COFF header (machine
// 0x14C, SizeOfOptionalHeader=0xE0), an OptionalHeader32 (magic 0x10B,
// ImageBase from the imageBase parameter, SizeOfHeaders=0x200, 16 zero data
// directories), one section header per section, and each section's raw
// data at 0x200-aligned file offsets — so the first section's raw data
// starts at file offset 0x200.
func buildPE32(t *testing.T, imageBase uint32, secs ...section) []byte {
	t.Helper()

	headersEnd := uint32(peOptOff + peSizeOfOpt + peSectionHdrs*len(secs))
	rawOff := alignUp(headersEnd, peFileAlign)

	total := int(rawOff)
	for _, s := range secs {
		total += int(alignUp(uint32(len(s.data)), peFileAlign))
	}
	buf := make([]byte, total)

	// DOS stub: MZ signature and e_lfanew pointing right after the stub.
	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3c:], peELFanew)

	// PE signature and COFF file header.
	copy(buf[peELFanew:], "PE\x00\x00")
	coff := buf[peELFanew+4:]
	binary.LittleEndian.PutUint16(coff[0:], 0x14C)             // Machine: i386
	binary.LittleEndian.PutUint16(coff[2:], uint16(len(secs))) // NumberOfSections
	binary.LittleEndian.PutUint16(coff[16:], peSizeOfOpt)      // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(coff[18:], 0x0102)           // Characteristics: executable, 32-bit

	// OptionalHeader32; the 16 data directories stay zero.
	opt := buf[peOptOff:]
	binary.LittleEndian.PutUint16(opt[0:], 0x10B)        // Magic: PE32
	binary.LittleEndian.PutUint32(opt[28:], imageBase)   // ImageBase
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)      // SectionAlignment
	binary.LittleEndian.PutUint32(opt[36:], peFileAlign) // FileAlignment
	binary.LittleEndian.PutUint32(opt[60:], rawOff)      // SizeOfHeaders
	binary.LittleEndian.PutUint32(opt[92:], 16)          // NumberOfRvaAndSizes

	// SizeOfImage: end of the last section, rounded up to SectionAlignment.
	if n := len(secs); n > 0 {
		last := secs[n-1]
		end := last.vaddr + max(last.vsize, uint32(len(last.data)))
		binary.LittleEndian.PutUint32(opt[56:], alignUp(end, 0x1000))
	}

	// Section headers followed by raw section data at aligned offsets.
	shOff := peOptOff + peSizeOfOpt
	for i, s := range secs {
		if len(s.name) > 8 {
			t.Fatalf("buildPE32: section name %q exceeds 8 bytes", s.name)
		}
		sh := buf[shOff+i*peSectionHdrs:]
		copy(sh[:8], s.name)
		binary.LittleEndian.PutUint32(sh[8:], s.vsize)              // VirtualSize
		binary.LittleEndian.PutUint32(sh[12:], s.vaddr)             // VirtualAddress
		binary.LittleEndian.PutUint32(sh[16:], uint32(len(s.data))) // SizeOfRawData
		binary.LittleEndian.PutUint32(sh[20:], rawOff)              // PointerToRawData

		copy(buf[rawOff:], s.data)
		rawOff += alignUp(uint32(len(s.data)), peFileAlign)
	}
	return buf
}

// Geometry of buildDefaultFixture: a PE32 image that satisfies
// exepatch.DefaultAnchors exactly, so run() works against it unchanged.
// .text raw data starts at file offset 0x200 and is 0x283000 bytes long,
// so every DefaultAnchors file offset (refill site 0x5AE66, register site
// 0x5ADB5, reset-password site 0x5AE58, cave pusha 0x28309A, call site
// 0x2830A7, cave add-esp 0x2830AE) lands inside it.
// .rdata maps at RVA 0x284000 (VA 0x684000 with the 0x400000 image base)
// and starts with the URL C-string the refill site's push immediate points
// at; the register and reset-password strings sit at raw offsets 0x120 and
// 0x140, and the kernel32.dll sanity string at 0x100.
const (
	fixtureImageBase      = 0x400000
	fixtureURL            = "http://old.example/"
	fixtureNewURL         = "https://new.example/"
	fixtureRegisterURL    = "http://register.example/"
	fixtureResetPwURL     = "http://resetpw.example/"
	fixtureNewRegisterURL = "https://reg.example/"
	fixtureNewResetPwURL  = "https://pw.example/"
	fixtureTextVSize      = 0x283000
	fixtureRdataVA        = 0x284000
	fixtureRdataSize      = 0x1000
	fixtureKernelOff      = 0x100 // .rdata raw offset of the sanity string
	fixtureRegisterOff    = 0x120 // .rdata raw offset of the register URL
	fixtureResetPwOff     = 0x140 // .rdata raw offset of the reset-password URL
	fixtureURLSite        = 0x5AE66
	fixtureRegisterSite   = 0x5ADB5
	fixtureResetPwSite    = 0x5AE58
	fixtureCavePusha      = 0x28309A
	fixtureCustomDllSite  = 0x2830A7
	fixtureCaveEsp        = 0x2830AE
)

// customDllOriginalSite are the seven enabled-state call-site bytes of
// DefaultAnchors.CustomDllOriginal.
var customDllOriginalSite = []byte{0x54, 0xff, 0x15, 0xf8, 0x61, 0x6e, 0x00}

// fixtureDLLName is the dll name planted in the fixture's code cave.
const fixtureDLLName = "fanta.dll"

// plantNamePushes writes the three stack pushes that spell name inside the
// cave at file offset p: `6a <c>` (imm8), `68 <le32>` and `68 <le32>`.
func plantNamePushes(data []byte, p int, name string) {
	var w [9]byte
	copy(w[:], name)
	data[p+1] = 0x6a
	data[p+2] = w[8]
	data[p+3] = 0x68
	binary.LittleEndian.PutUint32(data[p+4:], uint32(w[4])|uint32(w[5])<<8|uint32(w[6])<<16|uint32(w[7])<<24)
	data[p+8] = 0x68
	binary.LittleEndian.PutUint32(data[p+9:], uint32(w[0])|uint32(w[1])<<8|uint32(w[2])<<16|uint32(w[3])<<24)
}

// plantURLSite writes the `6a <len> 68 <le32 VA>` push site for the
// url C-string living at strVA into data at the file offset site.
func plantURLSite(data []byte, site int, url string, strVA uint32) {
	data[site] = 0x6a
	data[site+1] = byte(len(url))
	data[site+2] = 0x68
	binary.LittleEndian.PutUint32(data[site+3:], strVA)
}

// buildDefaultFixture builds a PE32 image resolvable under
// exepatch.DefaultAnchors: all four settings editable, refill URL
// fixtureURL, register URL fixtureRegisterURL, reset-password URL
// fixtureResetPwURL, customDll enabled, kernel32.dll present.
func buildDefaultFixture(t *testing.T) []byte {
	t.Helper()

	rdata := make([]byte, fixtureRdataSize)
	copy(rdata, fixtureURL) // NUL terminator from the zero fill
	copy(rdata[fixtureKernelOff:], "kernel32.dll")
	copy(rdata[fixtureRegisterOff:], fixtureRegisterURL)
	copy(rdata[fixtureResetPwOff:], fixtureResetPwURL)

	data := buildPE32(t, fixtureImageBase,
		section{name: ".text", vaddr: 0x1000, vsize: fixtureTextVSize, data: make([]byte, fixtureTextVSize)},
		section{name: ".rdata", vaddr: fixtureRdataVA, vsize: fixtureRdataSize, data: rdata},
	)

	// The three URL sites at their DefaultAnchors file offsets: 6a <len>
	// 68 <le32 VA> of the C-string in .rdata.
	plantURLSite(data, fixtureURLSite, fixtureURL, fixtureImageBase+fixtureRdataVA)
	plantURLSite(data, fixtureRegisterSite, fixtureRegisterURL, fixtureImageBase+fixtureRdataVA+fixtureRegisterOff)
	plantURLSite(data, fixtureResetPwSite, fixtureResetPwURL, fixtureImageBase+fixtureRdataVA+fixtureResetPwOff)

	// customDll code cave and call site at the DefaultAnchors file offsets.
	data[fixtureCavePusha] = 0x60 // pusha
	plantNamePushes(data, fixtureCavePusha, fixtureDLLName)
	copy(data[fixtureCustomDllSite:], customDllOriginalSite)
	data[fixtureCaveEsp] = 0x83 // add esp, 0x0c
	data[fixtureCaveEsp+1] = 0xc4
	data[fixtureCaveEsp+2] = 0x0c
	return data
}

// writeDefaultFixture writes the default fixture to
// <tempdir>/FantaTennis.exe and returns the path.
func writeDefaultFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "FantaTennis.exe")
	if err := os.WriteFile(path, buildDefaultFixture(t), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

// readFixture returns the current on-disk bytes of path.
func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return data
}

func TestRunShow(t *testing.T) {
	path := writeDefaultFixture(t)

	var buf bytes.Buffer
	if code := run([]string{"show", path}, &buf); code != 0 {
		t.Fatalf("run(show) exit = %d, want 0 (output: %s)", code, buf.String())
	}

	out := buf.String()
	if n := strings.Count(out, "\n"); n != 4 {
		t.Errorf("run(show) printed %d lines, want 4 (output: %q)", n, out)
	}
	for _, want := range []string{
		"refillUrl\teditable\t" + fixtureURL,
		"registerUrl\teditable\t" + fixtureRegisterURL,
		"resetPasswordUrl\teditable\t" + fixtureResetPwURL,
		"customDll\teditable\tenabled\t" + fixtureDLLName,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("run(show) output = %q, want a line containing %q", out, want)
		}
	}
}

func TestRunRefillURLPrintsCurrent(t *testing.T) {
	path := writeDefaultFixture(t)
	before := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"refill-url", path}, &buf); code != 0 {
		t.Fatalf("run(refill-url) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	if !strings.Contains(buf.String(), fixtureURL) {
		t.Errorf("run(refill-url) output = %q, want the current URL %q", buf.String(), fixtureURL)
	}
	if after := readFixture(t, path); !bytes.Equal(before, after) {
		t.Error("file changed by a read-only refill-url invocation")
	}
}

func TestRunRefillURLApplies(t *testing.T) {
	path := writeDefaultFixture(t)
	before := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"refill-url", path, fixtureNewURL}, &buf); code != 0 {
		t.Fatalf("run(refill-url new) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, fixtureNewURL) {
		t.Errorf("output = %q, want the new URL %q", out, fixtureNewURL)
	}
	sum := md5.Sum(readFixture(t, path))
	if want := "md5: " + hex.EncodeToString(sum[:]) + "\n"; !strings.Contains(out, want) {
		t.Errorf("output = %q, want the line %q", out, want)
	}
	if want := "backup: " + path + ".bak\n"; !strings.Contains(out, want) {
		t.Errorf("output = %q, want the backup line %q", out, want)
	}
	if bytes.Equal(before, readFixture(t, path)) {
		t.Error("file unchanged by refill-url apply")
	}
}

func TestRunRegisterURLPrintsCurrent(t *testing.T) {
	path := writeDefaultFixture(t)
	before := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"register-url", path}, &buf); code != 0 {
		t.Fatalf("run(register-url) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	if !strings.Contains(buf.String(), fixtureRegisterURL) {
		t.Errorf("run(register-url) output = %q, want the current URL %q", buf.String(), fixtureRegisterURL)
	}
	if after := readFixture(t, path); !bytes.Equal(before, after) {
		t.Error("file changed by a read-only register-url invocation")
	}
}

func TestRunRegisterURLApplies(t *testing.T) {
	path := writeDefaultFixture(t)
	before := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"register-url", path, fixtureNewRegisterURL}, &buf); code != 0 {
		t.Fatalf("run(register-url new) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, fixtureNewRegisterURL) {
		t.Errorf("output = %q, want the new URL %q", out, fixtureNewRegisterURL)
	}
	sum := md5.Sum(readFixture(t, path))
	if want := "md5: " + hex.EncodeToString(sum[:]) + "\n"; !strings.Contains(out, want) {
		t.Errorf("output = %q, want the line %q", out, want)
	}
	if want := "backup: " + path + ".bak\n"; !strings.Contains(out, want) {
		t.Errorf("output = %q, want the backup line %q", out, want)
	}
	if bytes.Equal(before, readFixture(t, path)) {
		t.Error("file unchanged by register-url apply")
	}
}

func TestRunResetPwURLPrintsCurrent(t *testing.T) {
	path := writeDefaultFixture(t)
	before := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"resetpw-url", path}, &buf); code != 0 {
		t.Fatalf("run(resetpw-url) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	if !strings.Contains(buf.String(), fixtureResetPwURL) {
		t.Errorf("run(resetpw-url) output = %q, want the current URL %q", buf.String(), fixtureResetPwURL)
	}
	if after := readFixture(t, path); !bytes.Equal(before, after) {
		t.Error("file changed by a read-only resetpw-url invocation")
	}
}

func TestRunResetPwURLApplies(t *testing.T) {
	path := writeDefaultFixture(t)
	before := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"resetpw-url", path, fixtureNewResetPwURL}, &buf); code != 0 {
		t.Fatalf("run(resetpw-url new) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, fixtureNewResetPwURL) {
		t.Errorf("output = %q, want the new URL %q", out, fixtureNewResetPwURL)
	}
	sum := md5.Sum(readFixture(t, path))
	if want := "md5: " + hex.EncodeToString(sum[:]) + "\n"; !strings.Contains(out, want) {
		t.Errorf("output = %q, want the line %q", out, want)
	}
	if want := "backup: " + path + ".bak\n"; !strings.Contains(out, want) {
		t.Errorf("output = %q, want the backup line %q", out, want)
	}
	if bytes.Equal(before, readFixture(t, path)) {
		t.Error("file unchanged by resetpw-url apply")
	}
}

func TestRunNoloadDisableAndEnable(t *testing.T) {
	path := writeDefaultFixture(t)
	original := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"noload", path}, &buf); code != 0 {
		t.Fatalf("run(noload) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	if want := "customDll\teditable\tdisabled\t" + fixtureDLLName; !strings.Contains(buf.String(), want) {
		t.Errorf("disable output = %q, want the disabled state with the dll name column", buf.String())
	}
	if bytes.Equal(original, readFixture(t, path)) {
		t.Fatal("file unchanged by noload disable")
	}

	buf.Reset()
	if code := run([]string{"noload", "--enable", path}, &buf); code != 0 {
		t.Fatalf("run(noload --enable) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	if want := "customDll\teditable\tenabled\t" + fixtureDLLName; !strings.Contains(buf.String(), want) {
		t.Errorf("enable output = %q, want the enabled state with the dll name column", buf.String())
	}
	if after := readFixture(t, path); !bytes.Equal(original, after) {
		t.Error("disable+enable did not round-trip the file to its original bytes")
	}
}

// TestRunRefillURLReportsBackupsUnderGlobMetaDir covers backup reporting
// when the user's path contains glob metacharacters (e.g. a directory
// literally named "[FT]"): both the pristine `.bak` and the timestamped
// snapshot must still be listed, which a filepath.Glob scan cannot do
// (ErrBadPattern) and a naive Glob match would silently mis-list.
func TestRunRefillURLReportsBackupsUnderGlobMetaDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "[FT]")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	path := filepath.Join(dir, "FantaTennis.exe")
	if err := os.WriteFile(path, buildDefaultFixture(t), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}

	var buf bytes.Buffer
	if code := run([]string{"refill-url", path, fixtureNewURL}, &buf); code != 0 {
		t.Fatalf("run(refill-url new) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	out := buf.String()

	var backups []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "backup: ") {
			backups = append(backups, strings.TrimPrefix(line, "backup: "))
		}
	}
	if want := path + ".bak"; len(backups) != 2 || backups[0] != want {
		t.Errorf("backup lines = %v, want exactly [%s.bak, <snapshot>]", backups, path)
	}
	if len(backups) != 2 {
		t.Fatalf("backup lines = %v, want exactly 2 (pristine .bak + timestamped snapshot)", backups)
	}
	if prefix := path + ".bak."; !strings.HasPrefix(backups[1], prefix) || len(backups[1]) <= len(prefix) {
		t.Errorf("second backup line = %q, want a timestamped snapshot %q...", backups[1], prefix)
	}
}

func TestRunUsageErrors(t *testing.T) {
	path := writeDefaultFixture(t)
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"unknown subcommand", []string{"frobnicate"}},
		{"show without path", []string{"show"}},
		{"refill-url without path", []string{"refill-url"}},
		{"register-url without path", []string{"register-url"}},
		{"resetpw-url without path", []string{"resetpw-url"}},
		{"noload without path", []string{"noload"}},
		{"noload --enable without path", []string{"noload", "--enable"}},
		{"dll-name without path", []string{"dll-name"}},
		{"dll-name with extra args", []string{"dll-name", path, "mod.dll", "extra"}},
		{"refill-url with extra args", []string{"refill-url", path, fixtureNewURL, "extra"}},
		{"register-url with extra args", []string{"register-url", path, fixtureNewRegisterURL, "extra"}},
		{"resetpw-url with extra args", []string{"resetpw-url", path, fixtureNewResetPwURL, "extra"}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if code := run(tc.args, &buf); code != 2 {
			t.Errorf("run(%v) exit = %d, want 2", tc.args, code)
		}
		if !strings.Contains(buf.String(), "usage:") {
			t.Errorf("run(%v) output = %q, want usage text", tc.args, buf.String())
		}
	}
}

func TestRunMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.exe")

	var buf bytes.Buffer
	if code := run([]string{"show", path}, &buf); code != 1 {
		t.Fatalf("run(show missing) exit = %d, want 1 (output: %s)", code, buf.String())
	}
	if !strings.Contains(buf.String(), "missing.exe") {
		t.Errorf("output = %q, want the error naming the missing file", buf.String())
	}
}

// TestRunNotEditableExitsOne covers the runtime-error contract for an
// unresolvable setting: a PE32 too small for any DefaultAnchors offset
// makes Apply fail with ErrNotEditable, which run reports as exit 1.
func TestRunNotEditableExitsOne(t *testing.T) {
	data := buildPE32(t, fixtureImageBase,
		section{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
		section{name: ".rdata", vaddr: 0x2000, vsize: 0x1000, data: make([]byte, 64)},
	)
	path := filepath.Join(t.TempDir(), "small.exe")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}

	var buf bytes.Buffer
	if code := run([]string{"noload", path}, &buf); code != 1 {
		t.Fatalf("run(noload) on unresolvable build exit = %d, want 1 (output: %s)", code, buf.String())
	}
	if !strings.Contains(buf.String(), "not editable") {
		t.Errorf("output = %q, want the ErrNotEditable text", buf.String())
	}
	if after := readFixture(t, path); !bytes.Equal(data, after) {
		t.Error("file changed despite the failed apply")
	}
}

// TestRunRefillURLRejectsEmptyValue covers the validation-error contract:
// a rejected value is a runtime error (exit 1), not a usage error.
func TestRunRefillURLRejectsEmptyValue(t *testing.T) {
	path := writeDefaultFixture(t)
	before := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"refill-url", path, ""}, &buf); code != 1 {
		t.Fatalf("run(refill-url empty) exit = %d, want 1 (output: %s)", code, buf.String())
	}
	if !strings.Contains(buf.String(), "empty URL") {
		t.Errorf("output = %q, want the validation error", buf.String())
	}
	if after := readFixture(t, path); !bytes.Equal(before, after) {
		t.Error("file changed by a rejected refill-url value")
	}
}

func TestRunDllNamePrintsCurrent(t *testing.T) {
	path := writeDefaultFixture(t)
	before := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"dll-name", path}, &buf); code != 0 {
		t.Fatalf("run(dll-name) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	want := "customDll\teditable\tenabled\t" + fixtureDLLName
	if !strings.Contains(buf.String(), want) {
		t.Errorf("run(dll-name) output = %q, want a line containing %q", buf.String(), want)
	}
	if after := readFixture(t, path); !bytes.Equal(before, after) {
		t.Error("file changed by a read-only dll-name invocation")
	}
}

func TestRunDllNameRenames(t *testing.T) {
	path := writeDefaultFixture(t)
	original := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"dll-name", path, "mod.dll"}, &buf); code != 0 {
		t.Fatalf("run(dll-name rename) exit = %d, want 0 (output: %s)", code, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, fixtureDLLName+"\n") {
		t.Errorf("rename output = %q, want the old name printed first", out)
	}
	if !strings.Contains(out, "mod.dll") {
		t.Errorf("rename output = %q, want the new name", out)
	}
	sum := md5.Sum(readFixture(t, path))
	if want := "md5: " + hex.EncodeToString(sum[:]) + "\n"; !strings.Contains(out, want) {
		t.Errorf("output = %q, want the line %q", out, want)
	}
	if want := "backup: " + path + ".bak\n"; !strings.Contains(out, want) {
		t.Errorf("output = %q, want the backup line %q", out, want)
	}
	if bytes.Equal(original, readFixture(t, path)) {
		t.Fatal("file unchanged by dll-name rename")
	}

	buf.Reset()
	if code := run([]string{"dll-name", path}, &buf); code != 0 {
		t.Fatalf("run(dll-name) after rename exit = %d, want 0 (output: %s)", code, buf.String())
	}
	if want := "customDll\teditable\tenabled\tmod.dll"; !strings.Contains(buf.String(), want) {
		t.Errorf("output after rename = %q, want a line containing %q", buf.String(), want)
	}
}

func TestRunDllNameRejectsInvalidName(t *testing.T) {
	path := writeDefaultFixture(t)
	before := readFixture(t, path)

	var buf bytes.Buffer
	if code := run([]string{"dll-name", path, "nope.exe"}, &buf); code != 1 {
		t.Fatalf("run(dll-name invalid) exit = %d, want 1 (output: %s)", code, buf.String())
	}
	if !strings.Contains(buf.String(), ".dll") {
		t.Errorf("output = %q, want the validation error", buf.String())
	}
	if after := readFixture(t, path); !bytes.Equal(before, after) {
		t.Error("file changed by a rejected dll name")
	}
}
