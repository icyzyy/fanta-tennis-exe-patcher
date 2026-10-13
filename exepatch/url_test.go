package exepatch

import (
	"encoding/binary"
	"testing"
)

// Fixture geometry shared by the resolveURL tests: .text at RVA 0x1000 (raw
// file data 0x200..0x400) and .rdata at RVA 0x2000 starting with the URL
// C-string.
const (
	urlFixtureBase         = 0x400000
	urlFixtureSite         = 0x240 // refill site, inside .text raw data
	urlFixtureRegisterSite = 0x250
	urlFixtureResetPwSite  = 0x260
	urlFixturePad          = 64 // spare zero bytes after the string's NUL in .rdata
)

// urlFixtureSites pairs each URL setting ID with the .text offset at which
// urlFixture can plant its site.
var urlFixtureSites = []struct {
	id   string
	site int
}{
	{settingIDRefillURL, urlFixtureSite},
	{settingIDRegisterURL, urlFixtureRegisterSite},
	{settingIDResetPwURL, urlFixtureResetPwSite},
}

// urlFixture builds a PE32 image with one URL setting's site planted at
// siteOff as `6a <len> 68 <le32 VA>` and the URL C-string at the start of
// .rdata, followed by a NUL and urlFixturePad spare zero bytes.
func urlFixture(t *testing.T, url string, siteOff int) ([]byte, *peInfo) {
	t.Helper()
	if len(url) > 255 {
		t.Fatalf("urlFixture: url of %d bytes exceeds the 255-byte C-string cap", len(url))
	}
	rdata := append([]byte(url), make([]byte, urlFixturePad+1)...)
	data := buildPE32(t, urlFixtureBase,
		testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
		testSection{name: ".rdata", vaddr: 0x2000, vsize: 0x1000, data: rdata},
	)
	if siteOff < 0x200 || siteOff+7 > 0x400 {
		t.Fatalf("urlFixture: site offset %#x outside .text raw data", siteOff)
	}
	data[siteOff] = 0x6a
	data[siteOff+1] = byte(len(url))
	data[siteOff+2] = 0x68
	binary.LittleEndian.PutUint32(data[siteOff+3:], urlFixtureBase+0x2000)
	p, err := parsePE32(data)
	if err != nil {
		t.Fatalf("urlFixture: parsePE32: %v", err)
	}
	return data, p
}

func TestResolveURLHappyPath(t *testing.T) {
	const url = "http://a.example/"
	data, p := urlFixture(t, url, urlFixtureSite)
	target, reason := resolveURL(data, p, urlFixtureSite)
	if reason != "" {
		t.Fatalf("resolveURL reason = %q, want %q", reason, "")
	}
	if target == nil {
		t.Fatal("resolveURL target = nil, want non-nil")
	}
	if target.site != urlFixtureSite {
		t.Errorf("site = %#x, want %#x", target.site, urlFixtureSite)
	}
	if target.current != url {
		t.Errorf("current = %q, want %q", target.current, url)
	}
	if want := p.sectionByName(".rdata").rawptr; target.strOff != want {
		t.Errorf("strOff = %#x, want %#x (start of .rdata raw data)", target.strOff, want)
	}
	if want := len(url) + urlFixturePad; target.capacity != want {
		t.Errorf("capacity = %d, want %d (string len + %d trailing zeros)", target.capacity, want, urlFixturePad)
	}
}

func TestResolveURLShapeMismatch(t *testing.T) {
	data, p := urlFixture(t, "http://a.example/", urlFixtureSite)
	for i := 0; i < 7; i++ {
		data[urlFixtureSite+i] = 0x90
	}
	target, reason := resolveURL(data, p, urlFixtureSite)
	if target != nil {
		t.Errorf("target = %+v, want nil", target)
	}
	if reason != "URL site not found in this build" {
		t.Errorf("reason = %q, want %q", reason, "URL site not found in this build")
	}
}

func TestResolveURLPointerUnmapped(t *testing.T) {
	data, p := urlFixture(t, "http://a.example/", urlFixtureSite)
	// Point the push immediate at a VA outside every section.
	binary.LittleEndian.PutUint32(data[urlFixtureSite+3:], urlFixtureBase+0x9000)
	target, reason := resolveURL(data, p, urlFixtureSite)
	if target != nil {
		t.Errorf("target = %+v, want nil", target)
	}
	if reason != "URL site not found in this build" {
		t.Errorf("reason = %q, want %q", reason, "URL site not found in this build")
	}
}

func TestResolveURLRejectsNonHTTPString(t *testing.T) {
	data, p := urlFixture(t, "ftp://x", urlFixtureSite)
	target, reason := resolveURL(data, p, urlFixtureSite)
	if target != nil {
		t.Errorf("target = %+v, want nil", target)
	}
	if reason != "URL site not found in this build" {
		t.Errorf("reason = %q, want %q", reason, "URL site not found in this build")
	}
}

func TestResolveURLRejectsLenByteMismatch(t *testing.T) {
	const url = "https://x.io/ab" // 15 bytes
	data, p := urlFixture(t, url, urlFixtureSite)
	data[urlFixtureSite+1] = 99
	target, reason := resolveURL(data, p, urlFixtureSite)
	if target != nil {
		t.Errorf("target = %+v, want nil", target)
	}
	if reason != "URL site not found in this build" {
		t.Errorf("reason = %q, want %q", reason, "URL site not found in this build")
	}
}

func TestResolveURLTruncatedSectionTail(t *testing.T) {
	const url = "http://a.example/"
	data, p := urlFixture(t, url, urlFixtureSite)
	strOff := p.sectionByName(".rdata").rawptr
	// Truncate the file inside .rdata's zero run: after the URL's NUL, with
	// exactly 3 spare zeros left, but well before the section header's
	// claimed end (rawptr + min(vsize, rawsz)). The capacity scan must be
	// clamped to the real file length instead of trusting the header.
	data = data[:strOff+uint32(len(url))+1+3]
	p, err := parsePE32(data)
	if err != nil {
		t.Fatalf("parsePE32(truncated fixture): %v", err)
	}
	target, reason := resolveURL(data, p, urlFixtureSite)
	if reason != "" {
		t.Fatalf("resolveURL reason = %q, want %q", reason, "")
	}
	if target == nil {
		t.Fatal("resolveURL target = nil, want non-nil")
	}
	if want := len(url) + 3; target.capacity != want {
		t.Errorf("capacity = %d, want %d (scan clamped to file length)", target.capacity, want)
	}
}

func TestResolveURLCapacity(t *testing.T) {
	const url = "http://a.example/"
	data, p := urlFixture(t, url, urlFixtureSite)
	strOff := p.sectionByName(".rdata").rawptr
	// Leave exactly three zero bytes after the string's NUL, then a guard byte.
	data[strOff+uint32(len(url))+4] = 0x01
	target, reason := resolveURL(data, p, urlFixtureSite)
	if reason != "" {
		t.Fatalf("resolveURL reason = %q, want %q", reason, "")
	}
	if target == nil {
		t.Fatal("resolveURL target = nil, want non-nil")
	}
	if want := len(url) + 3; target.capacity != want {
		t.Errorf("capacity = %d, want %d (string len + exactly 3 zeros)", target.capacity, want)
	}
}

// TestResolveURLEachSettingSite pins that the resolver works against each
// URL setting's own site offset: the happy path resolves the right site,
// and the shape guard rejects that same site when its bytes are damaged.
func TestResolveURLEachSettingSite(t *testing.T) {
	const url = "http://a.example/"
	for _, tc := range urlFixtureSites {
		t.Run(tc.id, func(t *testing.T) {
			data, p := urlFixture(t, url, tc.site)
			target, reason := resolveURL(data, p, tc.site)
			if reason != "" || target == nil {
				t.Fatalf("resolveURL(site %#x) = (%+v, %q), want a target", tc.site, target, reason)
			}
			if target.site != tc.site || target.current != url {
				t.Errorf("target = {site:%#x current:%q}, want {site:%#x current:%q}",
					target.site, target.current, tc.site, url)
			}

			data, p = urlFixture(t, url, tc.site)
			data[tc.site] = 0x90 // not push 6a
			target, reason = resolveURL(data, p, tc.site)
			if target != nil || reason != "URL site not found in this build" {
				t.Errorf("resolveURL(damaged site %#x) = (%+v, %q), want (nil, %q)",
					tc.site, target, reason, "URL site not found in this build")
			}
		})
	}
}
