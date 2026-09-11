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

import (
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/stretchr/testify/require"
)

// The two flags are declared per entry rather than derived, so the one thing
// that must never happen is an entry that forgot to declare them: false would
// then mean "needs an admin, holds one instance" by accident. A pointer tells
// the difference and the loader refuses the whole catalog.
func TestParseCuratedMCPServers_RequiresBothFlags(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		entry string
		want  string
	}{
		{
			name:  "neither declared",
			entry: `{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://a.example.com/mcp"}`,
			want:  "does not declare self_service",
		},
		{
			name:  "only self_service",
			entry: `{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://a.example.com/mcp","self_service":true}`,
			want:  "does not declare multi_instance",
		},
		{
			name:  "only multi_instance",
			entry: `{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://a.example.com/mcp","multi_instance":true}`,
			want:  "does not declare self_service",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseCuratedMCPServers([]byte(`{"servers":[` + tc.entry + `]}`))
			require.ErrorContains(t, err, tc.want)
			require.ErrorContains(t, err, "com.acme/mcp")
		})
	}
}

// A declared false must survive the load, which a bool alone could not tell
// from an absent field.
func TestParseCuratedMCPServers_KeepsDeclaredFalse(t *testing.T) {
	t.Parallel()

	servers, err := parseCuratedMCPServers([]byte(`{"servers":[
		{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://a.example.com/mcp","self_service":false,"multi_instance":false}
	]}`))
	require.NoError(t, err)
	require.Len(t, servers, 1)
	require.False(t, servers[0].SelfService)
	require.False(t, servers[0].MultiInstance)
}

// staticCredentialSlot reports whether the entry has anywhere to put a
// credential of its own: an auth header, or a secret URL variable.
func staticCredentialSlot(s domain.MCPServer) bool {
	if len(s.AuthHeaders) > 0 {
		return true
	}
	for _, v := range s.URLVariables {
		if v.Secret {
			return true
		}
	}
	return false
}

func clientCredentials(s domain.MCPServer) bool {
	return s.OAuth != nil &&
		strings.EqualFold(strings.TrimSpace(s.OAuth.GrantType), grantTypeClientCredentials)
}

func operatorRegistersClient(s domain.MCPServer) bool {
	return s.OAuth != nil &&
		strings.EqualFold(strings.TrimSpace(s.OAuth.Registration), "manual")
}

// The flags are data now, so nothing in the running gateway re-derives them and
// nothing would notice a wrong one. These are the claims each value makes about
// the entry it sits on, checked against that entry's own facts — the guard that
// replaces the derivation. An entry that breaks one of them is either mislabelled
// or is a shape the catalog has not seen before; either way it wants a human.
func TestCuratedCatalogFlagsAgreeWithTheEntry(t *testing.T) {
	t.Parallel()
	servers, err := loadCuratedMCPServers()
	require.NoError(t, err)
	require.Len(t, servers, 200, "the seed grew or shrank; re-audit the flags")

	multi, self := 0, 0
	for _, s := range servers {
		if s.MultiInstance {
			multi++
		}
		if s.SelfService {
			self++
		}

		// multi_instance: false claims there is nothing two registries of this
		// server could differ in. Anything an operator supplies contradicts it.
		if !s.MultiInstance {
			require.Empty(t, s.URLVariables, "%s: a templated URL differs per instance", s.Code)
			require.Empty(t, s.AuthHeaders, "%s: two credentials are two instances", s.Code)
			require.False(t, clientCredentials(s), "%s: the machine credential is the operator's", s.Code)
			require.False(t, operatorRegistersClient(s), "%s: the operator's own client differs", s.Code)
			if static, _ := s.SupportedAuthMethods(); static {
				t.Fatalf("%s: a static credential differs per instance", s.Code)
			}
		}

		// self_service: false claims a user cannot install it until an admin
		// supplies something. There has to be something to supply.
		if !s.SelfService {
			require.True(t,
				staticCredentialSlot(s) || clientCredentials(s) || operatorRegistersClient(s) ||
					(s.OAuth != nil && s.OAuth.Required && strings.TrimSpace(s.OAuth.Registration) == ""),
				"%s: nothing here needs an admin, so a user could install it", s.Code)
		}

		// self_service: true on a server whose credential is a static one is
		// only possible when that credential is per user — a secret URL variable
		// each user enters for themselves, never a shared header.
		if static, oauth := s.SupportedAuthMethods(); s.SelfService && static && !oauth {
			require.Empty(t, s.AuthHeaders, "%s: a shared header is an admin's to add", s.Code)
			require.True(t, staticCredentialSlot(s), "%s: nothing for a user to enter", s.Code)
		}
	}

	// Canaries: a change in these counts means entries moved between the two
	// answers, which is worth looking at deliberately.
	require.Equal(t, 98, multi, "multi_instance count changed")
	require.Equal(t, 115, self, "self_service count changed")
}

// The seed answers for a gateway standing on its own. A platform-held OAuth
// client is a deployment fact it cannot know, and it is the only thing that
// moves a declared flag after load — self_service, because the blocker it
// declared (an operator must register a client first) is gone.
//
// multi_instance stays as declared: the install form still offers an operator
// their own client id and secret for a manual-registration server, so two
// instances can still differ. This is the one behaviour that changed when the
// flags became data; before, the platform client also forced the server to a
// single instance.
func TestPlatformClientRaisesSelfServiceOnly(t *testing.T) {
	t.Parallel()
	const gmail = "com.google.workspace/gmail"

	without, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)
	entry, ok := without.GetByCode(gmail)
	require.True(t, ok)
	require.False(t, entry.SelfService, "an operator must register the client themselves")
	require.True(t, entry.MultiInstance, "their own client is what two instances differ in")

	with, err := NewMCPServerCatalog(mcpoauth.NewGoogleWorkspace("nt-client", "nt-secret"))
	require.NoError(t, err)
	entry, ok = with.GetByCode(gmail)
	require.True(t, ok)
	require.True(t, entry.SelfService, "the platform holds the client, so nothing is asked of an operator")
	require.True(t, entry.MultiInstance, "an operator may still bring their own client on another instance")

	// Nothing else moves: an entry the platform holds no client for is served
	// exactly as the seed declares it.
	untouched, ok := with.GetByCode("app.linear/mcp")
	require.True(t, ok)
	require.True(t, untouched.SelfService)
	require.True(t, untouched.MultiInstance)
	require.False(t, untouched.PlatformClient)
}
