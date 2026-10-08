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

package mcpoauth

import "testing"

func TestUsesProviderEndpoints(t *testing.T) {
	t.Parallel()
	const (
		authorize = "https://accounts.google.com/o/oauth2/v2/auth"
		token     = "https://oauth2.googleapis.com/token"
	)
	tests := []struct {
		name                string
		code, authz, tokenU string
		want                bool
	}{
		{"provider endpoints", GmailCode, authorize, token, true},
		{"empty endpoints", CalendarCode, "", "", true},
		{"legacy token host", DriveCode, authorize, "https://www.googleapis.com/oauth2/v4/token", true},
		{"host is case-insensitive", GmailCode, "https://Accounts.Google.com/o/oauth2/v2/auth", token, true},
		{"explicit 443", GmailCode, "https://accounts.google.com:443/o/oauth2/v2/auth", token, true},
		{"other token host", GmailCode, authorize, "https://idp.example.com/token", false},
		{"other authorize host", GmailCode, "https://accounts.google.com.example.com/auth", token, false},
		{"plain http", GmailCode, "http://accounts.google.com/o/oauth2/v2/auth", token, false},
		{"other port", GmailCode, authorize, "https://oauth2.googleapis.com:8443/token", false},
		{"userinfo in url", GmailCode, authorize, "https://user@oauth2.googleapis.com/token", false},
		{"unparsable", GmailCode, "https://%zz", token, false},
		{"code without shared client", "com.example/mcp", authorize, token, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := UsesProviderEndpoints(tt.code, tt.authz, tt.tokenU); got != tt.want {
				t.Fatalf("UsesProviderEndpoints(%q, %q, %q) = %v, want %v", tt.code, tt.authz, tt.tokenU, got, tt.want)
			}
		})
	}
}
