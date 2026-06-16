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

package consumer

import "testing"

func TestNewSlug_FormatAndUniqueness(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		slug, err := NewSlug()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !IsValidSlug(slug) {
			t.Fatalf("NewSlug() = %q, not a valid slug", slug)
		}
		if _, dup := seen[slug]; dup {
			t.Fatalf("NewSlug() produced duplicate %q within 1000 draws", slug)
		}
		seen[slug] = struct{}{}
	}
}

func TestIsValidSlug(t *testing.T) {
	t.Parallel()
	valid := []string{"X84Yhsy8", "aaaaaaaa", "00000000", "AZaz0912"}
	for _, s := range valid {
		if !IsValidSlug(s) {
			t.Fatalf("IsValidSlug(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "short", "toolongslug1", "bad/slu8", "espa\u00f1aab", "with sp8"}
	for _, s := range invalid {
		if IsValidSlug(s) {
			t.Fatalf("IsValidSlug(%q) = true, want false", s)
		}
	}
}
