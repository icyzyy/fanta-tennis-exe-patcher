// Package exepatch reads and applies binary patches to the FantaTennis.exe
// PE32 executable.
package exepatch

import (
	"bytes"
	"debug/pe"
	"fmt"
)

// sectionInfo is the subset of a PE section header the patcher needs.
type sectionInfo struct {
	name          string
	vaddr, vsize  uint32
	rawptr, rawsz uint32
}

// peInfo is the subset of a PE32 image header the patcher needs.
type peInfo struct {
	imageBase uint32
	sections  []sectionInfo
}

// parsePE32 parses data as a PE32 (i386) image and returns the image base and
// section table. PE64 images and non-PE data are rejected.
func parsePE32(data []byte) (*peInfo, error) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("not a PE32: %w", err)
	}
	oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return nil, fmt.Errorf("not a PE32: optional header is %T, want *pe.OptionalHeader32", f.OptionalHeader)
	}
	p := &peInfo{
		imageBase: oh32.ImageBase,
		sections:  make([]sectionInfo, 0, len(f.Sections)),
	}
	for _, s := range f.Sections {
		p.sections = append(p.sections, sectionInfo{
			name:   s.Name,
			vaddr:  s.VirtualAddress,
			vsize:  s.VirtualSize,
			rawptr: s.Offset,
			rawsz:  s.Size,
		})
	}
	return p, nil
}

// vaToFile maps va (an imageBase-relative virtual address) to a file offset
// within the image's raw section data, or false if the VA is unmapped.
func (p *peInfo) vaToFile(va uint32) (uint32, bool) {
	if va < p.imageBase {
		return 0, false
	}
	rva := va - p.imageBase
	for _, s := range p.sections {
		if rva < s.vaddr || rva >= s.vaddr+s.vsize {
			continue
		}
		off := rva - s.vaddr
		if off >= s.rawsz {
			return 0, false // inside the section's uninitialized tail
		}
		return s.rawptr + off, true
	}
	return 0, false
}

// sectionByName returns the section with the given name, or nil if there is
// no such section.
func (p *peInfo) sectionByName(name string) *sectionInfo {
	for i := range p.sections {
		if p.sections[i].name == name {
			return &p.sections[i]
		}
	}
	return nil
}
