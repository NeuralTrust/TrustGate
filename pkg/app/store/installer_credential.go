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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

const (
	auditProviderUnlinked = "mcp_provider_unlinked"
	auditRevocationFailed = "mcp_token_revocation_failed"
	uninstallAuditSource  = "store_uninstall"
	// credentialRevokeTimeout bounds the vendor call. It runs after the per-key
	// lock is released, so a Postgres advisory lock is not held for this long.
	credentialRevokeTimeout = 15 * time.Second
	// credentialReleaseTimeout bounds the lock, the local vault delete, and the
	// re-check. A caller disconnect must not abandon that section.
	credentialReleaseTimeout = 5 * time.Second
	// credentialLockReleaseTimeout bounds releasing the per-key lock.
	credentialLockReleaseTimeout = 5 * time.Second
)

// credentialReleaseLocker is the vault's per-key refresh lock
// (gateway|subject|provider). Redis takes it with SETNX; Postgres uses an
// advisory lock. Vaults without it still re-check after the row is gone.
type credentialReleaseLocker interface {
	AcquireRefreshLock(context.Context, ids.GatewayID, string, string) (func(context.Context) error, error)
}

// uninstallActive removes one installation and, when this was the last active
// install of a per-user credential, the vault row. The credential delete is
// attempted before the row is removed and again after, so two concurrent
// uninstalls that both observed the other row cannot leave the credential
// behind.
func (i *installer) uninstallActive(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	removed *installationdomain.Installation,
) error {
	if removed == nil {
		return nil
	}
	if i.vault == nil || !removed.IsActive() {
		return i.installs.DeleteByID(ctx, gatewayID, principalSub, removed.ID)
	}
	// Lock, local delete, and the post-delete re-check outlive the caller.
	// The vendor call is not in this section: it would hold a Postgres
	// advisory lock and its connection for the whole revocation.
	releaseCtx, releaseCancel := context.WithTimeout(context.WithoutCancel(ctx), credentialReleaseTimeout)
	defer releaseCancel()
	cache := map[string][]*registrydomain.Registry{}
	bound, err := i.boundRegistry(releaseCtx, gatewayID, removed, cache)
	if err != nil {
		return err
	}
	provider := registrydomain.ForwardedVaultProviderFor(registryForRevoke(bound, removed), nil)
	if provider == "" || registrydomain.CredentialSubject(bound, principalSub) != principalSub {
		return i.installs.DeleteByID(releaseCtx, gatewayID, principalSub, removed.ID)
	}
	cred, err := i.releasePerUserCredential(releaseCtx, gatewayID, principalSub, bound, removed, provider, cache)
	if err != nil {
		return err
	}
	i.revokeBestEffort(ctx, gatewayID, principalSub, bound, removed, cred)
	return nil
}

// releasePerUserCredential holds the per-key lock while it deletes the local
// credential and re-checks after the installation row is gone. The returned
// credential was removed and may be revoked only after the lock is released.
// If the delete fails before the row is removed, the error is returned with
// the installation still in place and the vendor is not called.
func (i *installer) releasePerUserCredential(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	bound *registrydomain.Registry,
	removed *installationdomain.Installation,
	provider string,
	cache map[string][]*registrydomain.Registry,
) (*vaultdomain.Credential, error) {
	unlock, err := i.lockPerUserCredential(ctx, gatewayID, principalSub, provider)
	if err != nil {
		return nil, err
	}
	defer unlock()
	cred, err := i.deleteCredentialIfUnused(ctx, gatewayID, principalSub, bound, removed, provider, cache)
	if err != nil {
		return nil, err
	}
	if err := i.installs.DeleteByID(ctx, gatewayID, principalSub, removed.ID); err != nil {
		return nil, err
	}
	leftover, err := i.deleteCredentialIfUnused(ctx, gatewayID, principalSub, bound, removed, provider, cache)
	if err != nil {
		return nil, err
	}
	if leftover != nil {
		return leftover, nil
	}
	return cred, nil
}

func (i *installer) lockPerUserCredential(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, provider string,
) (func(), error) {
	locker, ok := i.vault.(credentialReleaseLocker)
	if !ok {
		return func() {}, nil
	}
	unlock, err := locker.AcquireRefreshLock(ctx, gatewayID, principalSub, provider)
	if err != nil {
		return nil, fmt.Errorf("store: lock credential for uninstall: %w", err)
	}
	return func() {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialLockReleaseTimeout)
		defer cancel()
		if err := unlock(releaseCtx); err != nil && i.logger != nil {
			i.logger.Warn("store: failed to release credential lock", "error", err)
		}
	}, nil
}

// deleteCredentialIfUnused deletes the local vault credential when no other
// active install and no admin-provisioned registry still resolve to it. It
// does not call the vendor.
func (i *installer) deleteCredentialIfUnused(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	bound *registrydomain.Registry,
	removed *installationdomain.Installation,
	provider string,
	cache map[string][]*registrydomain.Registry,
) (*vaultdomain.Credential, error) {
	used, err := i.credentialStillUsed(ctx, gatewayID, principalSub, bound, removed, provider, cache)
	if err != nil || used {
		return nil, err
	}
	return i.deleteLocalCredential(ctx, gatewayID, principalSub, bound, provider)
}

func (i *installer) credentialStillUsed(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	bound *registrydomain.Registry,
	removed *installationdomain.Installation,
	provider string,
	cache map[string][]*registrydomain.Registry,
) (bool, error) {
	holds, err := i.installs.ListByPrincipal(ctx, gatewayID, principalSub)
	if err != nil {
		return false, fmt.Errorf("store: list installs: %w", err)
	}
	for _, other := range holds {
		if other == nil || other.ID == removed.ID || !other.IsActive() {
			continue
		}
		otherReg, err := i.boundRegistry(ctx, gatewayID, other, cache)
		if err != nil {
			return false, err
		}
		if registrydomain.ForwardedVaultProviderFor(registryForRevoke(otherReg, other), nil) != provider {
			continue
		}
		if registrydomain.CredentialSubject(otherReg, principalSub) != principalSub {
			continue
		}
		return true, nil
	}
	return i.perUserKeyHeldByAdminRegistry(ctx, gatewayID, principalSub, provider, bound)
}

// perUserKeyHeldByAdminRegistry reports whether an admin-provisioned registry
// — origin empty, or anything other than a store materialisation — forwards
// this principal's own credential under the same vault key. Those registries
// are dialed from the consumer they are bound to, with no installation row, so
// an install list cannot see them. The registry this install is bound to does
// not count: uninstall is disconnecting that one.
func (i *installer) perUserKeyHeldByAdminRegistry(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, provider string,
	bound *registrydomain.Registry,
) (bool, error) {
	regs, err := listRegistriesByGateway(ctx, i.registries, gatewayID)
	if err != nil {
		return false, err
	}
	for _, reg := range regs {
		if reg == nil || (bound != nil && reg.ID == bound.ID) {
			continue
		}
		if reg.MCPTarget != nil && reg.MCPTarget.Origin == registrydomain.MCPOriginStore {
			continue
		}
		if registrydomain.ForwardedVaultProviderFor(reg, nil) != provider {
			continue
		}
		if registrydomain.CredentialSubject(reg, principalSub) != principalSub {
			continue
		}
		return true, nil
	}
	return false, nil
}

func (i *installer) deleteLocalCredential(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	bound *registrydomain.Registry,
	provider string,
) (*vaultdomain.Credential, error) {
	cred, err := i.vault.Find(ctx, gatewayID, principalSub, provider)
	switch {
	case errors.Is(err, vaultdomain.ErrNotFound):
		return nil, nil
	case errors.Is(err, vaultdomain.ErrUndecryptable):
		i.logRevocationFailure(ctx, gatewayID, bound, err)
		cred = nil
	case err != nil:
		return nil, fmt.Errorf("store: read credential for uninstall: %w", err)
	}
	switch err := i.vault.Delete(ctx, gatewayID, principalSub, provider); {
	case errors.Is(err, vaultdomain.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("store: delete credential for uninstall: %w", err)
	}
	i.logUnlinked(ctx, gatewayID, bound)
	return cred, nil
}

// revokeBestEffort asks the vendor to revoke a credential that has already
// been removed from the vault. The caller must have released the per-key lock.
// A failure is logged and does not restore the local credential.
func (i *installer) revokeBestEffort(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	bound *registrydomain.Registry,
	removed *installationdomain.Installation,
	cred *vaultdomain.Credential,
) {
	if i.revoker == nil || cred == nil {
		return
	}
	revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialRevokeTimeout)
	defer cancel()
	if err := i.revoker.Revoke(revokeCtx, gatewayID, principalSub, registryForRevoke(bound, removed), cred); err != nil {
		i.logRevocationFailure(ctx, gatewayID, bound, err)
	}
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
