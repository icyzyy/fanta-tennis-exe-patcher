package exepatch

import "testing"

// TestDefaultAnchorsReturnsIndependentCopies pins the immutability
// contract of DefaultAnchors: every call returns a fresh Anchors whose
// CustomDllOriginal/CustomDllNops are freshly allocated, so no caller can mutate
// the backing arrays another caller (or the resolver) sees.
func TestDefaultAnchorsReturnsIndependentCopies(t *testing.T) {
	mutated := DefaultAnchors()
	clean := DefaultAnchors()
	if &mutated.CustomDllNops[0] == &clean.CustomDllNops[0] {
		t.Fatal("two DefaultAnchors() calls share the CustomDllNops backing array")
	}
	if &mutated.CustomDllOriginal[0] == &clean.CustomDllOriginal[0] {
		t.Fatal("two DefaultAnchors() calls share the CustomDllOriginal backing array")
	}

	// Mutating one result must not be visible anywhere else.
	mutated.CustomDllNops[0] = 0xCC
	mutated.CustomDllOriginal[0] = 0x00

	fresh := DefaultAnchors()
	if fresh.CustomDllNops[0] != 0x90 {
		t.Errorf("fresh CustomDllNops[0] = %#x, want 0x90 (mutation leaked)", fresh.CustomDllNops[0])
	}
	if fresh.CustomDllOriginal[0] != 0x54 {
		t.Errorf("fresh CustomDllOriginal[0] = %#x, want 0x54 (mutation leaked)", fresh.CustomDllOriginal[0])
	}
	if len(fresh.CustomDllNops) != 7 || len(fresh.CustomDllOriginal) != 7 {
		t.Errorf("fresh anchor lengths = (%d, %d), want (7, 7)", len(fresh.CustomDllOriginal), len(fresh.CustomDllNops))
	}

	// The resolver, given a fresh DefaultAnchors() copy, still resolves
	// both customDll states against the fixture.
	data, fa := exeFixture(t)
	fa.CustomDllOriginal = fresh.CustomDllOriginal
	fa.CustomDllNops = fresh.CustomDllNops
	if v, reason := resolveCustomDll(data, fa); v != customDllValueEnabled || reason != "" {
		t.Errorf("resolveCustomDll(enabled fixture) = (%q, %q), want (%q, \"\")", v, reason, customDllValueEnabled)
	}
	copy(data[fa.CustomDllSite:], fresh.CustomDllNops)
	if v, reason := resolveCustomDll(data, fa); v != customDllValueDisabled || reason != "" {
		t.Errorf("resolveCustomDll(nops fixture) = (%q, %q), want (%q, \"\")", v, reason, customDllValueDisabled)
	}
}
