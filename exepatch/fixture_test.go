package exepatch

import (
	"encoding/binary"
	"testing"
)

// testSection describes one section header plus its raw data for a
// buildPE32 fixture image.
type testSection struct {
	name  string
	vaddr uint32
	vsize uint32
	data  []byte
}

// Layout constants of the images produced by buildPE32.
const (
	fixtureELFanew     = 0x40                    // PE signature offset in the 64-byte DOS stub
	fixtureOptOff      = fixtureELFanew + 4 + 20 // start of the OptionalHeader32
	fixtureFileAlign   = 0x200                   // FileAlignment of the fixture images
	fixtureSectionHdrs = 40                      // size of one COFF section header
	fixtureSizeOfOpt   = 0xE0                    // SizeOfOptionalHeader (PE32 with 16 data directories)
)

// alignUp rounds v up to the next multiple of align (a power of two).
func alignUp(v, align uint32) uint32 {
	return (v + align - 1) &^ (align - 1)
}

// plantURLSite writes the `6a <len> 68 <le32 VA>` push site for the
// url C-string living at strVA into data. site is a file offset that must
// fall inside .text raw data (0x200..0x400 of a fixture image).
func plantURLSite(t *testing.T, data []byte, site int, url string, strVA uint32) {
	t.Helper()
	if site < 0x200 || site+7 > 0x400 {
		t.Fatalf("plantURLSite: site %#x outside .text raw data", site)
	}
	data[site] = 0x6a
	data[site+1] = byte(len(url))
	data[site+2] = 0x68
	binary.LittleEndian.PutUint32(data[site+3:], strVA)
}

// buildPE32 builds a minimal in-memory PE32 image: a 64-byte DOS stub (MZ
// signature, e_lfanew=0x40), the PE\0\0 signature, a COFF header (machine
// 0x14C, SizeOfOptionalHeader=0xE0), an OptionalHeader32 (magic 0x10B,
// ImageBase from the imageBase parameter, SizeOfHeaders=0x200, 16 zero data
// directories), one section header per testSection, and each section's raw
// data at 0x200-aligned file offsets — so the first section's raw data
// (e.g. .text) starts at file offset 0x200. The builder makes no assertions;
// it only fails on structurally impossible input such as an overlong name.
func buildPE32(t *testing.T, imageBase uint32, secs ...testSection) []byte {
	t.Helper()

	headersEnd := uint32(fixtureOptOff + fixtureSizeOfOpt + fixtureSectionHdrs*len(secs))
	rawOff := alignUp(headersEnd, fixtureFileAlign)

	total := int(rawOff)
	for _, s := range secs {
		total += int(alignUp(uint32(len(s.data)), fixtureFileAlign))
	}
	buf := make([]byte, total)

	// DOS stub: MZ signature and e_lfanew pointing right after the stub.
	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3c:], fixtureELFanew)

	// PE signature and COFF file header.
	copy(buf[fixtureELFanew:], "PE\x00\x00")
	coff := buf[fixtureELFanew+4:]
	binary.LittleEndian.PutUint16(coff[0:], 0x14C)             // Machine: i386
	binary.LittleEndian.PutUint16(coff[2:], uint16(len(secs))) // NumberOfSections
	binary.LittleEndian.PutUint16(coff[16:], fixtureSizeOfOpt) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(coff[18:], 0x0102)           // Characteristics: executable, 32-bit

	// OptionalHeader32; the 16 data directories stay zero.
	opt := buf[fixtureOptOff:]
	binary.LittleEndian.PutUint16(opt[0:], 0x10B)             // Magic: PE32
	binary.LittleEndian.PutUint32(opt[28:], imageBase)        // ImageBase
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)           // SectionAlignment
	binary.LittleEndian.PutUint32(opt[36:], fixtureFileAlign) // FileAlignment
	binary.LittleEndian.PutUint32(opt[60:], rawOff)           // SizeOfHeaders
	binary.LittleEndian.PutUint32(opt[92:], 16)               // NumberOfRvaAndSizes

	// SizeOfImage: end of the last section, rounded up to SectionAlignment.
	if n := len(secs); n > 0 {
		last := secs[n-1]
		end := last.vaddr + max(last.vsize, uint32(len(last.data)))
		binary.LittleEndian.PutUint32(opt[56:], alignUp(end, 0x1000))
	}

	// Section headers followed by raw section data at aligned offsets.
	shOff := fixtureOptOff + fixtureSizeOfOpt
	for i, s := range secs {
		if len(s.name) > 8 {
			t.Fatalf("buildPE32: section name %q exceeds 8 bytes", s.name)
		}
		sh := buf[shOff+i*fixtureSectionHdrs:]
		copy(sh[:8], s.name)
		binary.LittleEndian.PutUint32(sh[8:], s.vsize)              // VirtualSize
		binary.LittleEndian.PutUint32(sh[12:], s.vaddr)             // VirtualAddress
		binary.LittleEndian.PutUint32(sh[16:], uint32(len(s.data))) // SizeOfRawData
		binary.LittleEndian.PutUint32(sh[20:], rawOff)              // PointerToRawData

		copy(buf[rawOff:], s.data)
		rawOff += alignUp(uint32(len(s.data)), fixtureFileAlign)
	}
	return buf
}
