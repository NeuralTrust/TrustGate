package policy

import "testing"

func TestMode_IsValid(t *testing.T) {
	t.Parallel()
	valid := []Mode{ModeEnforce, ModeThrottle, ModeObserve}
	for _, m := range valid {
		if !m.IsValid() {
			t.Fatalf("Mode %q should be valid", m)
		}
	}
	for _, m := range []Mode{"", "block", "bogus"} {
		if m.IsValid() {
			t.Fatalf("Mode %q should be invalid", m)
		}
	}
}

func TestMode_Normalize(t *testing.T) {
	t.Parallel()
	if got := Mode("").Normalize(); got != DefaultMode {
		t.Fatalf("empty Normalize() = %q, want %q", got, DefaultMode)
	}
	if got := ModeObserve.Normalize(); got != ModeObserve {
		t.Fatalf("Normalize() = %q, want %q", got, ModeObserve)
	}
}

func TestDefaultMode_IsEnforce(t *testing.T) {
	t.Parallel()
	if DefaultMode != ModeEnforce {
		t.Fatalf("DefaultMode = %q, want %q", DefaultMode, ModeEnforce)
	}
}
