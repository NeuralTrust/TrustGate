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

package registry

import (
	"context"
	"io"
	"log/slog"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

type memoryRewriter struct {
	targets []*domain.MCPTarget
}

func (m *memoryRewriter) RewriteMCPTargets(_ context.Context, fix func(*domain.MCPTarget) bool) (domain.SecretsRewriteReport, error) {
	var report domain.SecretsRewriteReport
	for _, t := range m.targets {
		report.Scanned++
		if fix(t) {
			report.Fixed++
		}
	}
	return report, nil
}

type countingSealer struct{ calls int }

func (c *countingSealer) SealStoredSecrets(context.Context) (int, int, error) {
	c.calls++
	return 0, 0, nil
}

func TestBackfillStoredSecrets_ClearsOnlyCopiedSharedSecret(t *testing.T) {
	t.Parallel()
	cat := gmailCatalog(map[string]stubSharedOAuth{
		"com.google.workspace/gmail": {clientID: "nt-client", clientSecret: "nt-secret"},
	})
	shared := &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeForwarded, Registration: domain.RegistrationManual,
			ClientID: "nt-client", ClientSecret: "nt-secret"},
	}
	byo := &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeForwarded, Registration: domain.RegistrationManual,
			ClientID: "customer-client", ClientSecret: "customer-secret"},
	}
	other := &domain.MCPTarget{
		Code: "com.example/mcp",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeForwarded, Registration: domain.RegistrationManual,
			ClientID: "nt-client", ClientSecret: "kept"},
	}
	rewriter := &memoryRewriter{targets: []*domain.MCPTarget{shared, byo, other}}
	auths := &countingSealer{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	require.NoError(t, BackfillStoredSecrets(context.Background(), rewriter, auths, cat, logger))
	require.Equal(t, "nt-client", shared.Auth.ClientID)
	require.Empty(t, shared.Auth.ClientSecret)
	require.Equal(t, "customer-secret", byo.Auth.ClientSecret)
	require.Equal(t, "kept", other.Auth.ClientSecret)
	require.Equal(t, 1, auths.calls)

	report, err := rewriter.RewriteMCPTargets(context.Background(), func(t *domain.MCPTarget) bool {
		return clearSharedOAuthSecret(t, cat)
	})
	require.NoError(t, err)
	require.Zero(t, report.Fixed, "a second run must find nothing to change")
}

func TestClearSharedOAuthSecret_ClearsWhatTheSharedClientCannotUse(t *testing.T) {
	t.Parallel()
	cat := gmailCatalog(map[string]stubSharedOAuth{
		"com.google.workspace/gmail": {clientID: "nt-client", clientSecret: "nt-secret"},
	})
	target := func(tokenURL, secret string) *domain.MCPTarget {
		return &domain.MCPTarget{
			Code: "com.google.workspace/gmail",
			Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeForwarded, Registration: domain.RegistrationManual,
				ClientID: "nt-client", ClientSecret: secret,
				AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: tokenURL},
		}
	}

	staleCopy := target("https://oauth2.googleapis.com/token", "previous-shared-secret")
	require.True(t, clearSharedOAuthSecret(staleCopy, cat))
	require.Empty(t, staleCopy.Auth.ClientSecret)

	copiedElsewhere := target("https://idp.example.com/token", "nt-secret")
	require.True(t, clearSharedOAuthSecret(copiedElsewhere, cat), "the exact shared secret is cleared wherever it sits")
	require.Empty(t, copiedElsewhere.Auth.ClientSecret)

	// A secret stored next to the shared client's id cannot belong to any other
	// client; the platform's own is what the connect paths present.
	pairedWithSharedID := target("https://idp.example.com/token", "operator-secret")
	require.True(t, clearSharedOAuthSecret(pairedWithSharedID, cat))
	require.Empty(t, pairedWithSharedID.Auth.ClientSecret)

	ownClient := target("https://idp.example.com/token", "operator-secret")
	ownClient.Auth.ClientID = "operator-client"
	require.False(t, clearSharedOAuthSecret(ownClient, cat))
	require.Equal(t, "operator-secret", ownClient.Auth.ClientSecret)
}

type failingRewriter struct{}

func (failingRewriter) RewriteMCPTargets(context.Context, func(*domain.MCPTarget) bool) (domain.SecretsRewriteReport, error) {
	return domain.SecretsRewriteReport{}, context.DeadlineExceeded
}

func TestBackfillStoredSecrets_AuthsRunEvenWhenRegistriesStop(t *testing.T) {
	t.Parallel()
	auths := &countingSealer{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := BackfillStoredSecrets(context.Background(), failingRewriter{}, auths, gmailCatalog(nil), logger)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, 1, auths.calls)
}
