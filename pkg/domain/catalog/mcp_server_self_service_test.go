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

package catalog

import "testing"

func TestIsSelfService(t *testing.T) {
	cases := []struct {
		name string
		s    MCPServer
		want bool
	}{
		{"public server", MCPServer{AuthHint: "none"}, true},
		{"oauth auto registration", MCPServer{AuthHint: "oauth", OAuth: &MCPOAuth{Registration: "auto"}}, true},
		{"oauth no spec", MCPServer{AuthHint: "oauth"}, true},
		{"oauth manual without platform client", MCPServer{AuthHint: "oauth", OAuth: &MCPOAuth{Registration: "manual"}}, false},
		{"oauth manual with platform client", MCPServer{AuthHint: "oauth", OAuth: &MCPOAuth{Registration: "manual"}, PlatformClient: true}, true},
		{"oauth client_credentials", MCPServer{AuthHint: "oauth", OAuth: &MCPOAuth{GrantType: "client_credentials"}, PlatformClient: true}, false},
		{"oauth required, undeclared registration", MCPServer{AuthHint: "oauth", OAuth: &MCPOAuth{Required: true}}, false},
		{"api key header only", MCPServer{AuthHint: "static", AuthHeaders: []MCPAuthHeader{{Name: "Authorization", Secret: true}}}, false},
		{"static via secret url variable", MCPServer{AuthHint: "static", URLVariables: []MCPURLVariable{{Name: "token", Secret: true, Required: true}}}, true},
		{"dual static+oauth auto", MCPServer{AuthMethods: []string{"static", "oauth"}, AuthHeaders: []MCPAuthHeader{{Name: "Authorization"}}, OAuth: &MCPOAuth{Registration: "auto"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.IsSelfService(); got != tc.want {
				t.Fatalf("IsSelfService = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSupportedAuthMethods(t *testing.T) {
	static, oauth := MCPServer{AuthMethods: []string{"static", "oauth"}}.SupportedAuthMethods()
	if !static || !oauth {
		t.Fatal("explicit auth_methods must be honoured")
	}
	static, oauth = MCPServer{AuthHint: "static", AuthHeaders: []MCPAuthHeader{{Name: "X"}}}.SupportedAuthMethods()
	if !static || oauth {
		t.Fatal("static hint must derive static only")
	}
	static, oauth = MCPServer{AuthHint: "none"}.SupportedAuthMethods()
	if static || oauth {
		t.Fatal("public server offers no auth method")
	}
}
