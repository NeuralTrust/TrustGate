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

package vault

import "testing"

func TestProviderBoundToCode(t *testing.T) {
	const code = "com.vercel/mcp"
	cases := []struct {
		provider string
		want     bool
	}{
		{provider: code, want: true},
		{provider: code + "|abc123", want: true},
		{provider: "urlvar:" + code + ":token", want: true},
		{provider: code + "2", want: false},
		{provider: code + "2|abc", want: false},
		{provider: "urlvar:" + code + "2:token", want: false},
		{provider: "com.other/mcp", want: false},
	}
	for _, tc := range cases {
		if got := providerBoundToCode(tc.provider, code); got != tc.want {
			t.Fatalf("provider %q bound=%v want %v", tc.provider, got, tc.want)
		}
	}
}
