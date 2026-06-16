// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
