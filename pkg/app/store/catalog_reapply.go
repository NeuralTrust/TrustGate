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
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// CatalogViewer returns the registry an install or connect should use for this
// request. When the row is an untouched previous seed value with no live
// credentials, the result carries the current catalog shape and the argument
// is left unchanged. Every other row is returned as it was passed.
type CatalogViewer interface {
	ViewCurrentCatalog(ctx context.Context, reg *registrydomain.Registry) *registrydomain.Registry
}

// CatalogTargetSaver persists a registry whose catalog-derived fields were
// replaced. It does not re-validate: the caller already accepted the shape,
// including a catalog row that has no admin secret yet.
type CatalogTargetSaver interface {
	SaveCatalogTarget(ctx context.Context, reg *registrydomain.Registry) error
}

// DynamicClientChecker reports whether a dynamic OAuth client is cached for a
// catalog code. A nil checker is an unknown answer, and a forwarded auto row
// is then left untouched.
type DynamicClientChecker interface {
	HasDynamicClient(ctx context.Context, gatewayID ids.GatewayID, code string) (bool, error)
}

type vaultBoundStore interface {
	ExistsBound(ctx context.Context, gatewayID ids.GatewayID, code string) (bool, error)
}

// CatalogReapply decides whether one existing registry may take the current
// catalog URL, auth, and registration. It updates only an exact previous-seed
// match that has no live credential. Anything else, including a probe error,
// is left untouched.
type CatalogReapply struct {
	catalog CatalogReader
	saver   CatalogTargetSaver
	vault   vaultBoundStore
	dcr     DynamicClientChecker
	logger  *slog.Logger
	mu      sync.Mutex
	locks   map[string]*sync.Mutex
}

// NewCatalogReapply wires the install/connect reconciler. saver may be nil on
// a plane that only views the current shape; the control plane passes the
// saver that persists it. vault and dcr may be nil, which refuses any row
// whose credentials live outside the registry.
func NewCatalogReapply(
	catalog CatalogReader,
	saver CatalogTargetSaver,
	vault vaultdomain.Repository,
	dcr DynamicClientChecker,
	logger *slog.Logger,
) (*CatalogReapply, error) {
	if catalog == nil {
		return nil, ErrUnavailable
	}
	loadPreviousCatalog()
	if previousLoadErr != nil {
		return nil, previousLoadErr
	}
	if logger == nil {
		logger = slog.Default()
	}
	var bound vaultBoundStore
	if checker, ok := vault.(vaultBoundStore); ok {
		bound = checker
	}
	return &CatalogReapply{
		catalog: catalog,
		saver:   saver,
		vault:   bound,
		dcr:     dcr,
		logger:  logger,
		locks:   map[string]*sync.Mutex{},
	}, nil
}

// Reapply updates every listed registry that still matches its previous seed
// and holds no credential. A save failure is logged and skipped. The call
// itself does not fail: install and connect must keep working.
func (r *CatalogReapply) Reapply(ctx context.Context, gatewayID ids.GatewayID, regs []*registrydomain.Registry) {
	if r == nil {
		return
	}
	for _, reg := range regs {
		if reg == nil || reg.GatewayID != gatewayID {
			continue
		}
		r.reapplyOne(ctx, reg)
	}
}

func (r *CatalogReapply) reapplyOne(ctx context.Context, reg *registrydomain.Registry) {
	unlock := r.lockRegistry(reg.ID.String())
	defer unlock()
	next, oldFP, newFP, ok := r.decide(ctx, reg)
	if !ok || r.saver == nil {
		return
	}
	updated := *reg
	updated.MCPTarget = next
	updated.UpdatedAt = time.Now().UTC()
	if err := r.saver.SaveCatalogTarget(ctx, &updated); err != nil {
		r.logger.Warn("store: catalog reapply save failed",
			slog.String("catalog_code", registrydomain.StoreCode(reg)),
			slog.String("registry_id", reg.ID.String()),
			slog.String("error", err.Error()),
		)
		return
	}
	reg.MCPTarget = updated.MCPTarget
	reg.UpdatedAt = updated.UpdatedAt
	r.audit(ctx, registrydomain.StoreCode(reg), reg.ID, oldFP, newFP)
}

// ViewCurrentCatalog is the in-memory half of Reapply: the caller dials or
// connects with the current catalog shape without waiting for the snapshot,
// and without writing. A row that must not change is returned as passed.
func (r *CatalogReapply) ViewCurrentCatalog(ctx context.Context, reg *registrydomain.Registry) *registrydomain.Registry {
	if r == nil || reg == nil {
		return reg
	}
	unlock := r.lockRegistry(reg.ID.String())
	defer unlock()
	next, _, _, ok := r.decide(ctx, reg)
	if !ok {
		return reg
	}
	viewed := *reg
	viewed.MCPTarget = next
	return &viewed
}

func (r *CatalogReapply) lockRegistry(id string) func() {
	r.mu.Lock()
	lock := r.locks[id]
	if lock == nil {
		lock = &sync.Mutex{}
		r.locks[id] = lock
	}
	r.mu.Unlock()
	lock.Lock()
	return lock.Unlock
}

// decide reports the target to store when this row is an exact previous seed
// value with no credential. ok is false for every other case, including errors.
func (r *CatalogReapply) decide(ctx context.Context, reg *registrydomain.Registry) (next *registrydomain.MCPTarget, oldFP, newFP string, ok bool) {
	if reg == nil || reg.MCPTarget == nil {
		return nil, "", "", false
	}
	code := strings.TrimSpace(reg.MCPTarget.Code)
	if code == "" {
		return nil, "", "", false
	}
	entry, found := r.catalog.GetByCode(code)
	if !found {
		return nil, "", "", false
	}
	current, err := storedCatalogShape(entry)
	if err != nil {
		r.logger.Warn("store: catalog reapply current shape failed",
			slog.String("catalog_code", code),
			slog.String("error", err.Error()),
		)
		return nil, "", "", false
	}
	oldFP, err = catalogFingerprint(reg.MCPTarget)
	if err != nil {
		r.logger.Warn("store: catalog reapply fingerprint failed",
			slog.String("catalog_code", code),
			slog.String("error", err.Error()),
		)
		return nil, "", "", false
	}
	newFP, err = catalogFingerprint(current)
	if err != nil {
		return nil, "", "", false
	}
	if oldFP == newFP {
		return nil, "", "", false
	}
	previous, matched, err := previousFingerprint(code)
	if err != nil || !matched || previous != oldFP {
		return nil, "", "", false
	}
	if catalogCustomized(reg.MCPTarget) {
		return nil, "", "", false
	}
	if blocked, err := credentialsBlock(ctx, r.vault, r.dcr, reg); err != nil || blocked {
		if err != nil {
			r.logger.Warn("store: catalog reapply credential check failed",
				slog.String("catalog_code", code),
				slog.String("registry_id", reg.ID.String()),
				slog.String("error", err.Error()),
			)
		}
		return nil, "", "", false
	}
	if !acceptableCatalogWrite(reg, current) {
		return nil, "", "", false
	}
	if reg.MCPTarget != nil {
		current.Origin = reg.MCPTarget.Origin
		current.InstanceConfig = reg.MCPTarget.InstanceConfig
	}
	return current, oldFP, newFP, true
}

func (r *CatalogReapply) audit(ctx context.Context, code string, id ids.RegistryID, oldFP, newFP string) {
	r.logger.LogAttrs(ctx, slog.LevelInfo, "security audit",
		slog.String("event", "mcp_catalog_reapplied"),
		slog.String("catalog_code", code),
		slog.String("registry_id", id.String()),
		slog.String("old_fingerprint", oldFP),
		slog.String("new_fingerprint", newFP),
	)
}

// catalogCustomized reports fields an admin (or a stored secret) set that the
// catalog seed does not produce. Such a row is never rewritten.
func catalogCustomized(target *registrydomain.MCPTarget) bool {
	if target == nil {
		return true
	}
	if target.OpenAPI != nil {
		return true
	}
	if target.Source != "" && target.Source != registrydomain.MCPSourceRemote {
		return true
	}
	if len(target.Headers) > 0 || len(target.UnreadableHeaders) > 0 {
		return true
	}
	auth := target.Auth
	if auth == nil {
		return false
	}
	if strings.TrimSpace(auth.Value) != "" || auth.SecretUnreadable {
		return true
	}
	if strings.TrimSpace(auth.ClientID) != "" || strings.TrimSpace(auth.ClientSecret) != "" {
		return true
	}
	if auth.Account != "" || auth.Pattern != "" || strings.TrimSpace(auth.Audience) != "" ||
		strings.TrimSpace(auth.ExpectedAudience) != "" || strings.TrimSpace(auth.Scope) != "" ||
		strings.TrimSpace(auth.Actor) != "" || strings.TrimSpace(auth.IdentityID) != "" {
		return true
	}
	return false
}

// credentialsBlock reports whether a vault token, a dynamic client, or a
// secret on the row is bound to this registry. An unknown answer (nil probe,
// probe error) blocks the update.
func credentialsBlock(ctx context.Context, vault vaultBoundStore, dcr DynamicClientChecker, reg *registrydomain.Registry) (bool, error) {
	if reg == nil || reg.MCPTarget == nil {
		return true, nil
	}
	if rowHasCredential(reg.MCPTarget) {
		return true, nil
	}
	needsVault, needsDCR := needsOffRowCredentials(reg.MCPTarget)
	code := strings.TrimSpace(reg.MCPTarget.Code)
	if needsVault {
		if vault == nil {
			return true, nil
		}
		found, err := vault.ExistsBound(ctx, reg.GatewayID, code)
		if err != nil || found {
			return true, err
		}
	}
	if needsDCR {
		if dcr == nil {
			return true, nil
		}
		found, err := dcr.HasDynamicClient(ctx, reg.GatewayID, code)
		if err != nil || found {
			return true, err
		}
	}
	return false, nil
}

func rowHasCredential(target *registrydomain.MCPTarget) bool {
	if target == nil {
		return false
	}
	if len(target.Headers) > 0 || len(target.UnreadableHeaders) > 0 {
		return true
	}
	auth := target.Auth
	if auth == nil {
		return false
	}
	if strings.TrimSpace(auth.Value) != "" || auth.SecretUnreadable {
		return true
	}
	if strings.TrimSpace(auth.ClientID) != "" || strings.TrimSpace(auth.ClientSecret) != "" {
		return true
	}
	return false
}

func needsOffRowCredentials(target *registrydomain.MCPTarget) (vault, dcr bool) {
	if target == nil {
		return false, false
	}
	for _, variable := range target.URLVariables {
		if variable.Secret {
			vault = true
			break
		}
	}
	auth := target.Auth
	if auth == nil {
		return vault, false
	}
	switch auth.Mode {
	case registrydomain.MCPAuthModeForwarded:
		vault = true
		if auth.Registration == registrydomain.RegistrationAuto {
			dcr = true
		}
	case registrydomain.MCPAuthModeClientCredentials:
		vault = true
	case registrydomain.MCPAuthModeNone, registrydomain.MCPAuthModeStatic,
		registrydomain.MCPAuthModePassthrough, registrydomain.MCPAuthModeExchange, "":
	default:
		// An unrecognised mode is not a catalog shape. Treat it as carrying
		// a credential so the row stays untouched.
		vault = true
		dcr = true
	}
	return vault, dcr
}

// acceptableCatalogWrite allows a persist whose only validation failure is the
// secret the catalog does not carry. Any other validation error refuses the
// write. The live registry is not mutated.
func acceptableCatalogWrite(reg *registrydomain.Registry, next *registrydomain.MCPTarget) bool {
	if reg == nil || next == nil || strings.TrimSpace(reg.Name) == "" {
		return false
	}
	candidate := *reg
	candidate.MCPTarget = next
	err := candidate.Validate()
	if err == nil {
		return true
	}
	return credentialGapOnly(err)
}

func credentialGapOnly(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "forwarded with manual registration requires client_id"):
		return true
	case strings.Contains(msg, "auth mode static requires header and value"):
		return true
	case strings.Contains(msg, "client_credentials requires client_id and client_secret"):
		return true
	default:
		return false
	}
}
