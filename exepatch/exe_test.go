package exepatch

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture constants shared by the OpenExe/Settings tests: the three URL
// sites inside .text raw data (all clear of the customDll anchors at
// 0x273..0x28A) and the URLs they point at.
const (
	exeFixtureURL          = "http://a.example/"
	exeFixtureURLSite      = 0x240
	exeFixtureRegisterURL  = "http://register.example/"
	exeFixtureRegisterSite = 0x250
	exeFixtureResetPwURL   = "http://resetpw.example/"
	exeFixtureResetPwSite  = 0x260
)

// exeFixture builds a PE32 image in which all four settings resolve: the
// three URL sites at the .text offsets above hold `6a <len> 68 <le32 VA>`
// and point at their own URL C-strings packed at the start of .rdata, and
// the customDll cave/site are planted at the same .text offsets as the customDll
// tests. The .rdata section also carries the kernel32.dll sanity string.
// Returns the image bytes and the matching test Anchors.
func exeFixture(t *testing.T) ([]byte, Anchors) {
	t.Helper()
	a := Anchors{
		URLSite:           exeFixtureURLSite,
		RegisterSite:      exeFixtureRegisterSite,
		ResetPwSite:       exeFixtureResetPwSite,
		CustomDllSite:     customDllFixtureSite,
		CavePusha:         customDllFixturePusha,
		CaveAddEsp:        customDllFixtureAddEsp,
		CustomDllOriginal: []byte{0x54, 0xff, 0x15, 0xf8, 0x61, 0x6e, 0x00},
		CustomDllNops:     bytes.Repeat([]byte{0x90}, 7),
	}
	// The three URL strings are packed adjacent in .rdata, exactly as in
	// the real build: no zero run between them.
	rdata := append([]byte(exeFixtureURL), 0)
	registerOff := uint32(len(rdata))
	rdata = append(rdata, []byte(exeFixtureRegisterURL)...)
	rdata = append(rdata, 0)
	resetPwOff := uint32(len(rdata))
	rdata = append(rdata, []byte(exeFixtureResetPwURL)...)
	rdata = append(rdata, 0)
	rdata = append(rdata, []byte(sanityKernel32)...)
	rdata = append(rdata, 0)
	data := buildPE32(t, customDllFixtureBase,
		testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
		testSection{name: ".rdata", vaddr: 0x2000, vsize: 0x1000, data: rdata},
	)
	// URL sites (file offsets): 6a <len> 68 <le32 VA of the string.
	plantURLSite(t, data, exeFixtureURLSite, exeFixtureURL, customDllFixtureBase+0x2000)
	plantURLSite(t, data, exeFixtureRegisterSite, exeFixtureRegisterURL, customDllFixtureBase+0x2000+registerOff)
	plantURLSite(t, data, exeFixtureResetPwSite, exeFixtureResetPwURL, customDllFixtureBase+0x2000+resetPwOff)
	// customDll cave + call site.
	plantCustomDll(t, data, a)
	return data, a
}

func TestOpenExeReadsFileAndRequiresRdata(t *testing.T) {
	dir := t.TempDir()
	data, a := exeFixture(t)
	path := filepath.Join(dir, "FantaTennis.exe")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe(fixture with .rdata): %v", err)
	}
	settings := e.Settings()
	ids := make([]string, len(settings))
	for i, s := range settings {
		ids[i] = s.ID
	}
	wantIDs := []string{"refillUrl", "registerUrl", "resetPasswordUrl", "customDll"}
	if len(ids) != len(wantIDs) {
		t.Fatalf("Settings() IDs = %v, want %v", ids, wantIDs)
	}
	for i, want := range wantIDs {
		if ids[i] != want {
			t.Errorf("Settings()[%d].ID = %q, want %q", i, ids[i], want)
		}
	}
	// The handle resolves each setting out of the bytes read from the file.
	wantSettings := []struct {
		id, label, value string
		maxLength        int
	}{
		{settingIDRefillURL, "Cookie refill URL", exeFixtureURL, 127},
		{settingIDRegisterURL, "Register URL", exeFixtureRegisterURL, 127},
		{settingIDResetPwURL, "Reset password URL", exeFixtureResetPwURL, 127},
		{settingIDCustomDll, "Custom DLL load", "enabled", 0},
	}
	for i, want := range wantSettings {
		got := settings[i]
		if got.Label != want.label {
			t.Errorf("Settings()[%d].Label = %q, want %q", i, got.Label, want.label)
		}
		if got.Value != want.value {
			t.Errorf("Settings()[%d].Value = %q, want %q", i, got.Value, want.value)
		}
		if got.MaxLength != want.maxLength {
			t.Errorf("Settings()[%d].MaxLength = %d, want %d", i, got.MaxLength, want.maxLength)
		}
		if !got.Editable || got.Reason != "" {
			t.Errorf("Settings()[%s]: Editable=%v Reason=%q, want editable with empty reason", got.ID, got.Editable, got.Reason)
		}
	}

	// A fixture without .rdata is rejected.
	noRdataPath := filepath.Join(dir, "no-rdata.exe")
	noRdata := buildPE32(t, customDllFixtureBase,
		testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)})
	if err := os.WriteFile(noRdataPath, noRdata, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := OpenExe(noRdataPath, a); err == nil || !strings.Contains(err.Error(), "no .rdata section") {
		t.Errorf("OpenExe(fixture without .rdata) error = %v, want containing %q", err, "no .rdata section")
	}
}

func TestSettingsDisabledCarryReasons(t *testing.T) {
	// .text is all zeros: no URL site and no customDll cave resolves.
	data := buildPE32(t, customDllFixtureBase,
		testSection{name: ".text", vaddr: 0x1000, vsize: 0x200, data: make([]byte, 512)},
		testSection{name: ".rdata", vaddr: 0x2000, vsize: 0x1000, data: make([]byte, 64)},
	)
	path := filepath.Join(t.TempDir(), "no-anchors.exe")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, a := exeFixture(t)
	e, err := OpenExe(path, a)
	if err != nil {
		t.Fatalf("OpenExe: %v", err)
	}
	settings := e.Settings()
	if len(settings) != 4 {
		t.Fatalf("len(Settings()) = %d, want 4", len(settings))
	}
	for i, wantID := range []string{settingIDRefillURL, settingIDRegisterURL, settingIDResetPwURL, settingIDCustomDll} {
		s := settings[i]
		if s.ID != wantID {
			t.Errorf("Settings()[%d].ID = %q, want %q", i, s.ID, wantID)
		}
		if s.Editable || s.Value != "" || s.Reason == "" {
			t.Errorf("Settings()[%s] = {Editable:%v Value:%q Reason:%q}, want disabled with empty value and a reason",
				s.ID, s.Editable, s.Value, s.Reason)
		}
	}
}
