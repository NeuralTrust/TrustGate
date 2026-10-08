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
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// MCPTargetRewriter re-saves stored MCP targets so their credentials are
// encrypted, applying fix to each one under a row lock.
type MCPTargetRewriter interface {
	RewriteMCPTargets(ctx context.Context, fix func(*domain.MCPTarget) bool) (domain.SecretsRewriteReport, error)
}

// StoredSecretSealer encrypts credentials stored before encryption was
// introduced.
type StoredSecretSealer interface {
	SealStoredSecrets(ctx context.Context) (sealed, failed int, err error)
}

// BackfillStoredSecrets brings stored configuration up to the current storage
// rules: credentials encrypted, and no copy of the platform's shared OAuth
// client secret on a registry. It is idempotent and safe to run on every boot
// of every control-plane replica. A row it cannot handle is counted and left
// to the next run; only a failure to list the rows stops it.
func BackfillStoredSecrets(
	ctx context.Context,
	registries MCPTargetRewriter,
	auths StoredSecretSealer,
	catalog MCPAuthCatalog,
	logger *slog.Logger,
) error {
	report, regErr := registries.RewriteMCPTargets(ctx, func(t *domain.MCPTarget) bool {
		return clearSharedOAuthSecret(t, catalog)
	})
	authsSealed, authsFailed, authErr := auths.SealStoredSecrets(ctx)
	level := slog.LevelInfo
	if report.Failed > 0 || authsFailed > 0 {
		level = slog.LevelWarn
	}
	logger.Log(ctx, level, "stored secrets backfill finished",
		slog.Int("registries_scanned", report.Scanned),
		slog.Int("registries_encrypted", report.Encrypted),
		slog.Int("registries_shared_oauth_cleared", report.Fixed),
		slog.Int("registries_failed", report.Failed),
		slog.Int("auths_encrypted", authsSealed),
		slog.Int("auths_failed", authsFailed))
	if regErr != nil {
		return fmt.Errorf("backfill registry secrets: %w", regErr)
	}
	if authErr != nil {
		return fmt.Errorf("backfill auth secrets: %w", authErr)
	}
	return nil
}

// clearSharedOAuthSecret drops a stored copy of the platform's shared OAuth
// client secret and touches nothing else. It clears the exact shared secret
// wherever it sits, and any secret stored next to the shared client id on a
// target that uses the provider's endpoints, where the shared one is used at
// call time.
func clearSharedOAuthSecret(t *domain.MCPTarget, catalog MCPAuthCatalog) bool {
	if t == nil || t.Auth == nil || t.Auth.ClientSecret == "" || catalog == nil {
		return false
	}
	if t.Auth.Mode != domain.MCPAuthModeForwarded {
		return false
	}
	code := mcpoauth.SharedCode(t.Code, t.Auth.Provider)
	if creds, ok := sharedOAuthProvider(catalog).CredentialsFor(code); ok && t.Auth.ClientSecret == creds.ClientSecret {
		t.Auth.ClientSecret = ""
		return true
	}
	return bindSharedOAuth(t, catalog)
}
