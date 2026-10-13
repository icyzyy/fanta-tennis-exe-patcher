package exepatch

import (
	"encoding/binary"
	"strings"
)

// reasonURLSite is returned by resolveURL for every way a URL patch site
// can be missing or unusable in a given build.
const reasonURLSite = "URL site not found in this build"

// urlTarget locates a URL push site and its C-string operand.
type urlTarget struct {
	site     int
	strOff   uint32
	current  string
	capacity int
}

// cstringAt reads the NUL-terminated string starting at file offset off,
// reading at most max bytes. ok is false when off is past the end of data or
// no NUL occurs within max bytes or before the end of data.
func cstringAt(data []byte, off uint32, max int) (string, bool) {
	if uint64(off) >= uint64(len(data)) {
		return "", false
	}
	n := len(data) - int(off)
	if max < n {
		n = max
	}
	for i := 0; i < n; i++ {
		if data[int(off)+i] == 0 {
			return string(data[int(off) : int(off)+i]), true
		}
	}
	return "", false
}

// resolveURL locates the URL patch site at file offset site in data: the
// site must hold `6a <len> 68 <le32 VA>`, and the pointer must map to a
// NUL-terminated string that starts with "http" and matches the len byte.
// The caller passes the per-setting anchor (URLSite / RegisterSite /
// ResetPwSite). On success it returns the resolved target and an empty
// reason; otherwise it returns (nil, reason), where reason says why the
// setting is disabled in this build. Capacity is the string length plus
// the zero run after its terminator (within the string's section, within
// mapped virtual size), capped at urlHardLimit.
func resolveURL(data []byte, p *peInfo, site int) (*urlTarget, string) {
	// The site is `6a <len> 68 <le32 VA>`: seven bytes, site..site+6.
	if site < 0 || len(data)-site < 7 {
		return nil, reasonURLSite
	}
	if data[site] != 0x6a || data[site+2] != 0x68 {
		return nil, reasonURLSite
	}
	lenByte := data[site+1]
	ptr := binary.LittleEndian.Uint32(data[site+3 : site+7])
	strOff, ok := p.vaToFile(ptr)
	if !ok {
		return nil, reasonURLSite
	}
	str, ok := cstringAt(data, strOff, 255)
	if !ok {
		return nil, reasonURLSite
	}
	if !strings.HasPrefix(str, "http") || len(str) != int(lenByte) {
		return nil, reasonURLSite
	}
	// Capacity: the current string plus the zero run after its terminator,
	// bounded by the string's own section (within mapped virtual size) and
	// capped at the hard limit.
	end := uint64(len(data))
	for i := range p.sections {
		s := &p.sections[i]
		if uint64(strOff) >= uint64(s.rawptr) && uint64(strOff) < uint64(s.rawptr)+uint64(s.rawsz) {
			mapped := uint64(s.rawsz)
			if uint64(s.vsize) < mapped {
				mapped = uint64(s.vsize)
			}
			// Section headers are not validated against the real file
			// length; never let the scan run past the actual data.
			end = min(uint64(s.rawptr)+mapped, uint64(len(data)))
			break
		}
	}
	capacity := len(str)
	for off := uint64(strOff) + uint64(len(str)) + 1; capacity < urlHardLimit && off < end && data[off] == 0; off++ {
		capacity++
	}
	return &urlTarget{site: site, strOff: strOff, current: str, capacity: capacity}, ""
}
