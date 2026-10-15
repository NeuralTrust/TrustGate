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

package strutil

import (
	"strings"
	"testing"
)

func TestSanitizeUpstream(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"plain text untouched", "redirect_uri mismatch", 100, "redirect_uri mismatch"},
		{"control characters dropped", "bad\x00\x1b[31m\r\nvalue\x7f", 100, "bad[31m value"},
		{"whitespace collapsed", "  a \t\n b  ", 100, "a b"},
		{"capped", strings.Repeat("a", 500), 10, strings.Repeat("a", 10)},
		{"cap respects rune boundary", "ééééé", 5, "éé"},
		{"invalid utf8 dropped", "a\xffb", 100, "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeUpstream(tt.in, tt.max); got != tt.want {
				t.Fatalf("SanitizeUpstream(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

func TestIsBoundedPrintable(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"opaque id", "00u1abcd", true},
		{"email", "ana@example.com", true},
		{"unicode name", "Zoë", true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 257), false},
		{"control char", "ab\x00cd", false},
		{"newline", "ab\ncd", false},
		{"padded", " ab", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBoundedPrintable(tt.in, 256); got != tt.want {
				t.Fatalf("IsBoundedPrintable(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
