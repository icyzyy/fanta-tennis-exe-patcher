package exepatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realExeCases pairs each real-world file with the setting values
// verified against it: the patched FantaTennis.exe and its pristine
// .bak. The keys used to look the settings up are settingIDRefillURL,
// settingIDRegisterURL, settingIDResetPwURL and settingIDCustomDll.
var realExeCases = []struct {
	file                   string
	refillURL, registerURL string
	resetPwURL, customDll  string
}{
	{
		"FantaTennis.exe",
		"https://gamefaqs.gamespot.com/",
		"http://visa.mysquare.in.th/agreement.asp",
		"http://visa.mysquare.in.th/forgot_visa.asp",
		"disabled",
	},
	{
		"FantaTennis.exe.bak",
		"http://www.cookiecard.in.th",
		"http://visa.mysquare.in.th/agreement.asp",
		"http://visa.mysquare.in.th/forgot_visa.asp",
		"enabled",
	},
}

// findSetting returns the setting with the given ID, failing the test if
// it is absent (Settings always yields all four known IDs).
func findSetting(t *testing.T, settings []Setting, id string) Setting {
	t.Helper()
	for _, s := range settings {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("setting %q not found", id)
	return Setting{}
}

// TestIntegrationRealExeReadOnly opens the real FantaTennis.exe and its
// pristine backup from FANTA_EXE_DIR (read-only: no Apply, no writes) and
// asserts all four settings resolve as verified. It skips when
// FANTA_EXE_DIR is unset and asserts file mtimes are untouched across the
// reads.
func TestIntegrationRealExeReadOnly(t *testing.T) {
	dir := os.Getenv("FANTA_EXE_DIR")
	if dir == "" {
		t.Skip("FANTA_EXE_DIR not set; skipping real-exe integration test")
	}

	// Stat both files before any open so the mtime guard covers the
	// whole read sequence.
	before := map[string]int64{}
	for _, c := range realExeCases {
		p := filepath.Join(dir, c.file)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		before[p] = info.ModTime().UnixNano()
	}

	for _, c := range realExeCases {
		p := filepath.Join(dir, c.file)
		e, err := OpenExe(p, DefaultAnchors())
		if err != nil {
			t.Fatalf("OpenExe(%s): %v", p, err)
		}
		settings := e.Settings()

		refill := findSetting(t, settings, settingIDRefillURL)
		if !refill.Editable {
			t.Errorf("%s: refillUrl not editable: %s", c.file, refill.Reason)
		} else if refill.Value != c.refillURL {
			t.Errorf("%s: refillUrl = %q, want %q", c.file, refill.Value, c.refillURL)
		}

		register := findSetting(t, settings, settingIDRegisterURL)
		if !register.Editable {
			t.Errorf("%s: registerUrl not editable: %s", c.file, register.Reason)
		} else if register.Value != c.registerURL {
			t.Errorf("%s: registerUrl = %q, want %q", c.file, register.Value, c.registerURL)
		}

		resetPw := findSetting(t, settings, settingIDResetPwURL)
		if !resetPw.Editable {
			t.Errorf("%s: resetPasswordUrl not editable: %s", c.file, resetPw.Reason)
		} else if resetPw.Value != c.resetPwURL {
			t.Errorf("%s: resetPasswordUrl = %q, want %q", c.file, resetPw.Value, c.resetPwURL)
		}

		customDll := findSetting(t, settings, settingIDCustomDll)
		if !customDll.Editable {
			t.Errorf("%s: customDll not editable: %s", c.file, customDll.Reason)
		} else if customDll.Value != c.customDll {
			t.Errorf("%s: customDll = %q, want %q", c.file, customDll.Value, c.customDll)
		}

		// The cave's name pushes must decode on both real builds.
		name, err := e.CustomDllName()
		if err != nil {
			t.Errorf("%s: CustomDllName: %v", c.file, err)
		} else if !strings.HasSuffix(name, ".dll") || name == ".dll" {
			t.Errorf("%s: CustomDllName() = %q, want a non-empty .dll name", c.file, name)
		}
	}

	// Reads must not modify the files: mtimes after the opens and
	// Settings calls equal the ones taken before.
	for p, want := range before {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("re-stat %s: %v", p, err)
		}
		if got := info.ModTime().UnixNano(); got != want {
			t.Errorf("mtime of %s changed: %d -> %d", p, want, got)
		}
	}
}
