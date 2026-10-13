package exepatch

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParsePE32RejectsNonPE(t *testing.T) {
	data := append([]byte("MZ"), make([]byte, 100)...)
	_, err := parsePE32(data)
	if err == nil || !strings.Contains(err.Error(), "not a PE32") {
		t.Fatalf("parsePE32(non-PE data) error = %v, want containing %q", err, "not a PE32")
	}
}

func TestParsePE32RejectsPE64(t *testing.T) {
	data := buildPE32(t, 0x400000)
	// Rewrite the optional-header magic to PE32+ (0x20B).
	binary.LittleEndian.PutUint16(data[fixtureOptOff:], 0x20B)
	_, err := parsePE32(data)
	if err == nil || !strings.Contains(err.Error(), "PE32") {
		t.Fatalf("parsePE32(PE32+ magic) error = %v, want mentioning PE32", err)
	}
}

func TestParsePE32SectionsAndMapping(t *testing.T) {
	data := buildPE32(t, 0x400000,
		testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
		testSection{name: ".rdata", vaddr: 0x2000, vsize: 0x1000, data: make([]byte, 512)},
	)
	p, err := parsePE32(data)
	if err != nil {
		t.Fatalf("parsePE32: %v", err)
	}
	if p.imageBase != 0x400000 {
		t.Fatalf("imageBase = %#x, want %#x", p.imageBase, 0x400000)
	}
	if len(p.sections) != 2 {
		t.Fatalf("len(sections) = %d, want 2", len(p.sections))
	}

	// .rdata raw data starts at 0x200 (headers) + 0x200 (.text raw) = 0x400,
	// so VA imageBase+0x2004 maps to file offset 0x404.
	got, ok := p.vaToFile(0x400000 + 0x2004)
	if !ok || got != 0x404 {
		t.Fatalf("vaToFile(imageBase+0x2004) = (%#x, %v), want (0x404, true)", got, ok)
	}
	// Inside .rdata's virtual size but past its raw data: nothing in the file.
	if _, ok := p.vaToFile(0x400000 + 0x2200); ok {
		t.Fatal("vaToFile(beyond .rdata raw data) ok = true, want false")
	}
	// A VA in the gap between sections is unmapped.
	if _, ok := p.vaToFile(0x400000 + 0x4000); ok {
		t.Fatal("vaToFile(unmapped VA) ok = true, want false")
	}

	s := p.sectionByName(".rdata")
	if s == nil {
		t.Fatal(`sectionByName(".rdata") = nil, want non-nil`)
	}
	if s.vaddr != 0x2000 || s.vsize != 0x1000 {
		t.Fatalf(`sectionByName(".rdata") = {vaddr: %#x, vsize: %#x}, want {vaddr: 0x2000, vsize: 0x1000}`, s.vaddr, s.vsize)
	}
	if p.sectionByName(".nope") != nil {
		t.Fatal(`sectionByName(".nope") != nil, want nil`)
	}
}

func TestParsePE32NonDefaultImageBase(t *testing.T) {
	const imageBase = 0x10000000
	data := buildPE32(t, imageBase,
		testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
		testSection{name: ".rdata", vaddr: 0x2000, vsize: 0x1000, data: make([]byte, 512)},
	)
	p, err := parsePE32(data)
	if err != nil {
		t.Fatalf("parsePE32: %v", err)
	}
	if p.imageBase != imageBase {
		t.Fatalf("imageBase = %#x, want %#x", p.imageBase, imageBase)
	}
	if got, ok := p.vaToFile(imageBase + 0x2004); !ok || got != 0x404 {
		t.Fatalf("vaToFile(imageBase+0x2004) = (%#x, %v), want (0x404, true)", got, ok)
	}
	// A VA below the image base is unmapped.
	if _, ok := p.vaToFile(0x400000 + 0x2004); ok {
		t.Fatal("vaToFile(VA below image base) ok = true, want false")
	}
}
