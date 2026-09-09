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

package catalog_test

import (
	"testing"

	catalog "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

// Instances exist so one server can be shelved twice with different
// configuration. The question each case asks is the same: could two registries
// of this server differ in anything an operator supplies?
func TestMCPServer_SupportsInstances(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		server catalog.MCPServer
		want   bool
		why    string
	}{
		{
			name: "templated url",
			server: catalog.MCPServer{
				AuthHint:     "oauth",
				URLVariables: []catalog.MCPURLVariable{{Name: "account_url", Required: true}},
				OAuth:        &catalog.MCPOAuth{Required: true, Registration: "auto"},
			},
			want: true,
			why:  "two Snowflake schemas are two different servers to reach",
		},
		{
			name: "optional url variable still differentiates",
			server: catalog.MCPServer{
				AuthHint:     "oauth",
				URLVariables: []catalog.MCPURLVariable{{Name: "region"}},
				OAuth:        &catalog.MCPOAuth{Required: true, Registration: "auto"},
			},
			want: true,
			why:  "an operator who fills it in on one instance and not the other has two",
		},
		{
			name: "static credential",
			server: catalog.MCPServer{
				AuthHint:    "static",
				AuthHeaders: []catalog.MCPAuthHeader{{Name: "Authorization", Required: true, Secret: true}},
			},
			want: true,
			why:  "two API keys are two accounts on the same service",
		},
		{
			name: "operator-registered oauth client",
			server: catalog.MCPServer{
				AuthHint: "oauth",
				OAuth:    &catalog.MCPOAuth{Required: true, Registration: "manual"},
			},
			want: true,
			why:  "the client id and secret are the operator's, and can differ",
		},
		{
			name: "client credentials",
			server: catalog.MCPServer{
				AuthHint: "oauth",
				OAuth:    &catalog.MCPOAuth{Required: true, GrantType: "client_credentials"},
			},
			want: true,
			why:  "the machine credential is the operator's, and can differ",
		},
		{
			// The case that prompted the rule.
			name: "fixed url behind per-user oauth",
			server: catalog.MCPServer{
				AuthHint: "oauth",
				OAuth:    &catalog.MCPOAuth{Required: true, Registration: "auto"},
			},
			want: false,
			why:  "the gateway registers itself and each user signs in; nothing to configure",
		},
		{
			name: "platform-held oauth client",
			server: catalog.MCPServer{
				AuthHint:       "oauth",
				PlatformClient: true,
				OAuth:          &catalog.MCPOAuth{Required: true, Registration: "manual"},
			},
			want: false,
			why:  "the client is not the operator's to differ on",
		},
		{
			name:   "public server",
			server: catalog.MCPServer{AuthHint: "none"},
			want:   false,
			why:    "one URL, no credential, nothing to vary",
		},
		{
			name: "tenant-hosted with no declared variables",
			server: catalog.MCPServer{
				AuthHint: "oauth",
				OAuth:    &catalog.MCPOAuth{Registration: ""},
			},
			want: false,
			why:  "per-instance discovery says nothing about what an operator configures",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.server.SupportsInstances(); got != tc.want {
				t.Fatalf("SupportsInstances() = %v, want %v: %s", got, tc.want, tc.why)
			}
		})
	}
}
