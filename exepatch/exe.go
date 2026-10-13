package exepatch

import (
	"errors"
	"os"
)

// customDll setting metadata; the URL setting IDs live in anchors.go beside
// the other shared constants.
const (
	settingIDCustomDll      = "customDll"
	settingLabelRefillURL   = "Cookie refill URL"
	settingLabelRegisterURL = "Register URL"
	settingLabelResetPwURL  = "Reset password URL"
	settingLabelCustomDll   = "Custom DLL load"
)

// Setting is one patchable value read out of an open FantaTennis.exe.
// When Editable is false the build did not match: Value is empty and
// Reason says why. MaxLength is the longest value Apply accepts (0 for
// the enum-valued customDll setting).
type Setting struct {
	ID        string
	Label     string
	Value     string
	Editable  bool
	Reason    string
	MaxLength int
}

// Exe is an open handle over one FantaTennis.exe file: the bytes as read,
// their parsed PE32 view, and the anchors they resolve against. All
// methods resolve from this snapshot; nothing is remembered between
// opens.
type Exe struct {
	path    string
	data    []byte
	pe      *peInfo
	anchors Anchors
}

// OpenExe reads path, parses it as a PE32 image, and requires a .rdata
// section. Other section names and anchor mismatches are left to the
// per-setting resolvers in Settings.
func OpenExe(path string, a Anchors) (*Exe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := parsePE32(data)
	if err != nil {
		return nil, err
	}
	if p.sectionByName(".rdata") == nil {
		return nil, errors.New("no .rdata section")
	}
	return &Exe{path: path, data: data, pe: p, anchors: a}, nil
}

// Settings resolves all four settings independently against the bytes read
// at OpenExe time, in the fixed order
// [refillUrl, registerUrl, resetPasswordUrl, customDll].
func (e *Exe) Settings() []Setting {
	return []Setting{
		e.urlSetting(settingIDRefillURL, settingLabelRefillURL, e.anchors.URLSite),
		e.urlSetting(settingIDRegisterURL, settingLabelRegisterURL, e.anchors.RegisterSite),
		e.urlSetting(settingIDResetPwURL, settingLabelResetPwURL, e.anchors.ResetPwSite),
		e.customDllSetting(),
	}
}

// urlSetting builds one URL setting from the resolver's outcome against
// site: editable with the current value on success, disabled with the
// resolver's reason otherwise. Every URL setting shares the refill
// pipeline, so MaxLength is always urlHardLimit.
func (e *Exe) urlSetting(id, label string, site int) Setting {
	s := Setting{
		ID:        id,
		Label:     label,
		Editable:  true,
		MaxLength: urlHardLimit,
	}
	if target, reason := resolveURL(e.data, e.pe, site); target == nil {
		s.Editable = false
		s.Reason = reason
	} else {
		s.Value = target.current
	}
	return s
}

// customDllSetting builds the customDll setting from the resolver's outcome.
func (e *Exe) customDllSetting() Setting {
	s := Setting{
		ID:       settingIDCustomDll,
		Label:    settingLabelCustomDll,
		Editable: true,
	}
	if value, reason := resolveCustomDll(e.data, e.anchors); reason != "" {
		s.Editable = false
		s.Reason = reason
	} else {
		s.Value = value
	}
	return s
}
