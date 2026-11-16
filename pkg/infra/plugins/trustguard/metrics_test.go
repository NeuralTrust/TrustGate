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

package trustguard

import "testing"

func TestEngineLabel(t *testing.T) {
	cases := map[string]string{
		"":      "v1",
		"  ":    "v1",
		"v1":    "v1",
		"V1":    "v1",
		"v2":    "v2",
		" V2 ":  "v2",
		"v3":    "unknown",
		"other": "unknown",
	}
	for header, want := range cases {
		if got := engineLabel(header); got != want {
			t.Errorf("engineLabel(%q) = %q, want %q", header, got, want)
		}
	}
}
