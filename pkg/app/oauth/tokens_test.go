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

package oauth

import (
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

func TestUpstreamScopes(t *testing.T) {
	t.Parallel()
	entraLogin := []string{"api://gw/mcp.access", "offline_access"}
	tests := []struct {
		name      string
		required  []string
		login     []string
		requested string
		want      string
	}{
		{name: "no login scopes keeps the requested and required scopes", required: []string{"mcp.access"}, requested: "openid profile", want: "openid profile mcp.access"},
		{name: "no login scopes on refresh sends the required scopes", required: []string{"mcp.access"}, want: "mcp.access"},
		{name: "nothing configured sends nothing"},
		{
			name:      "login scopes drop the bare short name and the required scopes",
			required:  []string{"mcp.access"},
			login:     entraLogin,
			requested: "mcp.access openid offline_access",
			want:      "api://gw/mcp.access offline_access openid",
		},
		{name: "login scopes drop non-protocol requests", login: entraLogin, requested: "files.read profile", want: "api://gw/mcp.access offline_access profile"},
		{name: "login scopes keep protocol scopes", login: []string{"api://gw/mcp.access"}, requested: "openid email offline_access", want: "api://gw/mcp.access openid email offline_access"},
		{name: "login scopes de-duplicate", login: []string{"openid", "api://gw/mcp.access", "openid"}, requested: "openid openid", want: "openid api://gw/mcp.access"},
		{name: "login scopes on refresh", required: []string{"mcp.access"}, login: entraLogin, want: "api://gw/mcp.access offline_access"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &authdomain.OAuth2Config{RequiredScopes: tc.required, LoginScopes: tc.login}
			if got := upstreamScopes(cfg, tc.requested); got != tc.want {
				t.Fatalf("upstreamScopes(%q) = %q, want %q", tc.requested, got, tc.want)
			}
		})
	}
}
