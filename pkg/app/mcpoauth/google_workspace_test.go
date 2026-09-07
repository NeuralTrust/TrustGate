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

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewGoogleWorkspace_RequiresBoth(t *testing.T) {
	t.Parallel()

	_, ok := NewGoogleWorkspace("", "secret").CredentialsFor(GmailCode)
	require.False(t, ok)
	_, ok = NewGoogleWorkspace("id", "").CredentialsFor(GmailCode)
	require.False(t, ok)
	_, ok = NewGoogleWorkspace("  ", "  ").CredentialsFor(GmailCode)
	require.False(t, ok)
}

func TestNewGoogleWorkspace_CredentialsForKnownCodes(t *testing.T) {
	t.Parallel()

	p := NewGoogleWorkspace("nt-client", "nt-secret")
	for _, code := range []string{GmailCode, CalendarCode, DriveCode, "  " + GmailCode + "  "} {
		got, ok := p.CredentialsFor(code)
		require.True(t, ok, code)
		require.Equal(t, "nt-client", got.ClientID)
		require.Equal(t, "nt-secret", got.ClientSecret)
	}
}

func TestNewGoogleWorkspace_IgnoresOtherCatalogCodes(t *testing.T) {
	t.Parallel()

	p := NewGoogleWorkspace("nt-client", "nt-secret")
	_, ok := p.CredentialsFor("com.google.cloud/compute")
	require.False(t, ok)
	_, ok = p.CredentialsFor("com.slack/mcp")
	require.False(t, ok)
	_, ok = p.CredentialsFor("")
	require.False(t, ok)
}
