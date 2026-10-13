package exepatch

import "bytes"

// Anchors locates the patch sites within a FantaTennis.exe build. Tests
// inject small offsets into synthetic PE32 fixtures; DefaultAnchors
// returns the offsets of the known release build.
type Anchors struct {
	URLSite, RegisterSite, ResetPwSite, CustomDllSite, CavePusha, CaveAddEsp int
	CustomDllOriginal, CustomDllNops                                         []byte
}

// The site/offset anchors of the known release build, as plain consts.
const (
	defaultURLSite       = 0x5AE66
	defaultRegisterSite  = 0x5ADB5
	defaultResetPwSite   = 0x5AE58
	defaultCustomDllSite = 0x2830A7
	defaultCavePusha     = 0x28309A
	defaultCaveAddEsp    = 0x2830AE
)

// defaultAnchorOriginal and defaultAnchorNops are the byte patterns
// DefaultAnchors hands out; they are never exposed themselves, only
// copied into each returned Anchors.
var (
	defaultAnchorOriginal = []byte{0x54, 0xff, 0x15, 0xf8, 0x61, 0x6e, 0x00}
	defaultAnchorNops     = bytes.Repeat([]byte{0x90}, 7)
)

// DefaultAnchors returns the verified anchor values of the known
// FantaTennis.exe release build. Every call returns a fresh Anchors with
// freshly allocated CustomDllOriginal and CustomDllNops copies, so no consumer can
// mutate the package's values or another consumer's view through the
// shared byte slices.
func DefaultAnchors() Anchors {
	return Anchors{
		URLSite:           defaultURLSite,
		RegisterSite:      defaultRegisterSite,
		ResetPwSite:       defaultResetPwSite,
		CustomDllSite:     defaultCustomDllSite,
		CavePusha:         defaultCavePusha,
		CaveAddEsp:        defaultCaveAddEsp,
		CustomDllOriginal: bytes.Clone(defaultAnchorOriginal),
		CustomDllNops:     bytes.Clone(defaultAnchorNops),
	}
}

// Setting IDs and sanity constants shared across the package.
const (
	settingIDRefillURL   = "refillUrl"
	settingIDRegisterURL = "registerUrl"
	settingIDResetPwURL  = "resetPasswordUrl"
	urlHardLimit         = 127
	sanityKernel32       = "kernel32.dll"
)
