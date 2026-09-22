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
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

// self_service is declared per entry rather than derived, so the one thing that
// must never happen is an entry that forgot to declare it: false would then mean
// "needs an admin" by accident. A pointer tells the difference and the loader
// refuses the whole catalog.
func TestParseCuratedMCPServers_RequiresSelfService(t *testing.T) {
	t.Parallel()

	_, err := parseCuratedMCPServers([]byte(
		`{"servers":[{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://a.example.com/mcp"}]}`))

	require.ErrorContains(t, err, "does not declare self_service")
	require.ErrorContains(t, err, "com.acme/mcp")
}

// A declared false must survive the load, which a bool alone could not tell
// from an absent field.
func TestParseCuratedMCPServers_KeepsDeclaredFalse(t *testing.T) {
	t.Parallel()

	servers, err := parseCuratedMCPServers([]byte(`{"servers":[
		{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://a.example.com/mcp","self_service":false}
	]}`))
	require.NoError(t, err)
	require.Len(t, servers, 1)
	require.False(t, servers[0].SelfService)
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

	self := 0
	for _, s := range servers {
		if s.SelfService {
			self++
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

	// Canary: a change in this count means entries moved between the two
	// answers, which is worth looking at deliberately.
	require.Equal(t, 115, self, "self_service count changed")
}

// The seed answers for a gateway standing on its own. A platform-held OAuth
// client is a deployment fact it cannot know, and it is the only thing that
// moves a declared flag after load — self_service, because the blocker it
// declared (an operator must register a client first) is gone.
func TestPlatformClientRaisesSelfServiceOnly(t *testing.T) {
	t.Parallel()
	const gmail = "com.google.workspace/gmail"

	without, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)
	entry, ok := without.GetByCode(gmail)
	require.True(t, ok)
	require.False(t, entry.SelfService, "an operator must register the client themselves")

	with, err := NewMCPServerCatalog(mcpoauth.NewGoogleWorkspace("nt-client", "nt-secret"))
	require.NoError(t, err)
	entry, ok = with.GetByCode(gmail)
	require.True(t, ok)
	require.True(t, entry.SelfService, "the platform holds the client, so nothing is asked of an operator")

	// Nothing else moves: an entry the platform holds no client for is served
	// exactly as the seed declares it.
	untouched, ok := with.GetByCode("app.linear/mcp")
	require.True(t, ok)
	require.True(t, untouched.SelfService)
	require.False(t, untouched.PlatformClient)
}

// A closed URL variable lets one entry cover what would otherwise be a
// near-duplicate per region. The values are substituted into the upstream URL,
// so each one has to pass the same rules a typed value would, and a set with a
// value nobody can pick — or two that collide — is an authoring slip the seed
// should not carry.
func TestCuratedCatalog_ClosedURLVariablesDeclareUsableOptions(t *testing.T) {
	t.Parallel()
	servers, err := loadCuratedMCPServers()
	require.NoError(t, err)

	for _, s := range servers {
		for _, v := range s.URLVariables {
			if !v.HasOptions() {
				continue
			}
			seen := make(map[string]struct{}, len(v.Options))
			for _, option := range v.Options {
				require.NotEmpty(t, option.Value, "%s: variable %q has an empty option", s.Code, v.Name)
				require.NotEmpty(t, option.Label, "%s: option %q has nothing to pick it by", s.Code, option.Value)
				require.NoError(t, registrydomain.ValidateURLValue(asRegistryURLVariable(v), option.Value),
					"%s: option %q would be refused at install", s.Code, option.Value)
				_, dup := seen[option.Value]
				require.False(t, dup, "%s: option %q is declared twice", s.Code, option.Value)
				seen[option.Value] = struct{}{}
			}
		}
	}
}

// Vanta publishes one MCP host per region and they do not share a shape: the US
// host carries no region label at all, so no single template spells all three.
// The region is the choice, and the entry that covers them is one.
func TestCuratedCatalog_VantaIsOneEntryPerRegionChoice(t *testing.T) {
	t.Parallel()
	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)

	for _, gone := range []string{"com.vanta/mcp-eu", "com.vanta/mcp-aus"} {
		_, ok := cat.GetByCode(gone)
		require.False(t, ok, "%s: a region is an option on the entry, not an entry", gone)
	}

	entry, ok := cat.GetByCode("com.vanta/mcp")
	require.True(t, ok)
	require.Equal(t, "https://{host}/mcp", entry.URL)
	require.Len(t, entry.URLVariables, 1)
	require.Equal(t, []string{"mcp.vanta.com", "mcp.eu.vanta.com", "mcp.aus.vanta.com"},
		optionValues(entry.URLVariables[0]))

	// The audience has to follow the region. A literal would pin every region to
	// whichever one the entry was written for; resource_metadata derives it from
	// the URL the region resolves to.
	require.NotNil(t, entry.OAuth)
	require.Empty(t, entry.OAuth.Resource, "a literal resource cannot be regional")
	require.True(t, entry.OAuth.ResourceMetadata)
}

func optionValues(v domain.MCPURLVariable) []string {
	out := make([]string, 0, len(v.Options))
	for _, option := range v.Options {
		out = append(out, option.Value)
	}
	return out
}

// asRegistryURLVariable is the shape the install path validates against, so the
// seed guard runs the real rules rather than a copy of them.
func asRegistryURLVariable(v domain.MCPURLVariable) registrydomain.MCPURLVariable {
	out := registrydomain.MCPURLVariable{
		Name:     v.Name,
		Required: v.Required,
		Secret:   v.Secret,
		In:       v.In,
	}
	for _, option := range v.Options {
		out.Options = append(out.Options, registrydomain.MCPURLVariableOption{
			Value: option.Value,
			Label: option.Label,
		})
	}
	return out
}
