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

package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

const (
	auditProviderUnlinked = "mcp_provider_unlinked"
	auditRevocationFailed = "mcp_token_revocation_failed"
	uninstallAuditSource  = "store_uninstall"
)

// releasePerUserCredential deletes the principal's vault credential when this
// uninstall removes the last active installation that resolves to its key.
// The installation row is left in place when the vault delete fails.
func (i *installer) releasePerUserCredential(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	removed *installationdomain.Installation,
) error {
	if i == nil || i.vault == nil || removed == nil || !removed.IsActive() {
		return nil
	}
	cache := map[string][]*registrydomain.Registry{}
	bound, err := i.boundRegistry(ctx, gatewayID, removed, cache)
	if err != nil {
		return err
	}
	provider := registrydomain.ForwardedVaultProvider(bound)
	if provider == "" || registrydomain.CredentialSubject(bound, principalSub) != principalSub {
		return nil
	}
	holds, err := i.installs.ListByPrincipal(ctx, gatewayID, principalSub)
	if err != nil {
		return fmt.Errorf("store: list installs: %w", err)
	}
	for _, other := range holds {
		if other == nil || other.ID == removed.ID || !other.IsActive() {
			continue
		}
		otherReg, err := i.boundRegistry(ctx, gatewayID, other, cache)
		if err != nil {
			return err
		}
		if registrydomain.ForwardedVaultProvider(otherReg) != provider {
			continue
		}
		if registrydomain.CredentialSubject(otherReg, principalSub) != principalSub {
			continue
		}
		return nil
	}

	cred, err := i.vault.Find(ctx, gatewayID, principalSub, provider)
	switch {
	case errors.Is(err, vaultdomain.ErrNotFound):
		cred = nil
	case errors.Is(err, vaultdomain.ErrUndecryptable):
		i.logRevocationFailure(ctx, gatewayID, bound, err)
		cred = nil
	case err != nil:
		return fmt.Errorf("store: read credential for uninstall: %w", err)
	}
	if cred != nil && i.revoker != nil {
		if rerr := i.revoker.Revoke(ctx, gatewayID, principalSub, registryForRevoke(bound, removed), cred); rerr != nil {
			i.logRevocationFailure(ctx, gatewayID, bound, rerr)
		}
	}
	switch err := i.vault.Delete(ctx, gatewayID, principalSub, provider); {
	case errors.Is(err, vaultdomain.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("store: delete credential for uninstall: %w", err)
	}
	i.logUnlinked(ctx, gatewayID, bound)
	return nil
}

func (i *installer) boundRegistry(
	ctx context.Context,
	gatewayID ids.GatewayID,
	in *installationdomain.Installation,
	cache map[string][]*registrydomain.Registry,
) (*registrydomain.Registry, error) {
	if in == nil {
		return nil, nil
	}
	if id, ok := registrydomain.ParseCustomStoreCode(in.CatalogCode); ok {
		regs, err := findCustomRegistry(ctx, i.registries, gatewayID, id)
		if err != nil {
			return nil, err
		}
		if len(regs) == 0 {
			return nil, nil
		}
		return regs[0], nil
	}
	code := strings.TrimSpace(in.CatalogCode)
	regs, ok := cache[code]
	if !ok {
		var err error
		regs, err = findRegistriesByCode(ctx, i.registries, gatewayID, code)
		if err != nil {
			return nil, err
		}
		if cache != nil {
			cache[code] = regs
		}
	}
	if !in.RegistryID.IsNil() {
		return pickRegistry(regs, in.RegistryID), nil
	}
	if len(regs) == 0 {
		return nil, nil
	}
	return regs[0], nil
}

// registryForRevoke copies per-user URL values onto a registry clone so
// revocation can discover the upstream the principal actually dials. The
// shelved registry is left unchanged.
func registryForRevoke(reg *registrydomain.Registry, in *installationdomain.Installation) *registrydomain.Registry {
	if reg == nil || reg.MCPTarget == nil || !reg.MCPTarget.HasURLVariables() || in == nil || len(in.Config) == 0 {
		return reg
	}
	cp := *reg
	tgt := *reg.MCPTarget
	values := make(map[string]string, len(tgt.InstanceConfig)+len(in.Config))
	for k, v := range tgt.InstanceConfig {
		values[k] = v
	}
	for k, v := range in.Config {
		values[k] = v
	}
	tgt.InstanceConfig = values
	cp.MCPTarget = &tgt
	return &cp
}

func (i *installer) logUnlinked(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) {
	if i.logger == nil || reg == nil {
		return
	}
	provider := ""
	if auth := forwardedAuthOf(reg); auth != nil {
		provider = auth.Provider
	}
	i.logger.LogAttrs(ctx, slog.LevelInfo, "security audit",
		slog.String("event", auditProviderUnlinked),
		slog.String("gateway_id", gatewayID.String()),
		slog.String("registry_id", reg.ID.String()),
		slog.String("provider_id", provider),
		slog.String("source", uninstallAuditSource),
	)
}

func (i *installer) logRevocationFailure(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry, err error) {
	if i.logger == nil || err == nil {
		return
	}
	provider := ""
	registryID := ""
	if reg != nil {
		registryID = reg.ID.String()
		if auth := forwardedAuthOf(reg); auth != nil {
			provider = auth.Provider
		}
	}
	i.logger.LogAttrs(ctx, slog.LevelWarn, "security audit",
		slog.String("event", auditRevocationFailed),
		slog.String("gateway_id", gatewayID.String()),
		slog.String("registry_id", registryID),
		slog.String("provider_id", provider),
		slog.String("source", uninstallAuditSource),
		slog.String("error", err.Error()),
	)
}
