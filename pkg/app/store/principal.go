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
	"strings"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// PrincipalPreview is the admin read of one principal's Store state on a
// gateway: what they have installed (or requested) and which company sources
// they have linked their own account to. It powers the Portal preview ("what
// does this user see?") and never exposes credential material — only whether a
// connection exists, which account it is for, and whether it needs a reconnect.
//
//go:generate mockery --name=PrincipalPreview --dir=. --output=./mocks --filename=store_principal_preview_mock.go --case=underscore --with-expecter
type PrincipalPreview interface {
	Preview(ctx context.Context, gatewayID ids.GatewayID, principalSub string) (*PrincipalState, error)
}

// PrincipalState is the principal's Store state on one gateway.
type PrincipalState struct {
	PrincipalSub string
	Installs     []PrincipalInstall
	Connections  []PrincipalConnection
}

// PrincipalInstall is one Store instance the principal holds: installed,
// pending approval, or revoked (kept for audit, so the Portal can say "denied").
type PrincipalInstall struct {
	InstanceID  ids.InstallationID
	Code        string
	Name        string
	RegistryID  ids.RegistryID
	Registry    string
	Status      installationdomain.Status
	InstalledBy string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PrincipalConnection is the state of one company source that needs the
// principal's own account (forwarded-auth registry), linked or not.
type PrincipalConnection struct {
	Provider       string
	Code           string
	RegistryID     ids.RegistryID
	Registry       string
	Linked         bool
	AccountRef     string
	ExpiresAt      time.Time
	NeedsReconnect bool
}

type principalPreview struct {
	installs   installationdomain.Repository
	registries RegistryLister
	catalog    CatalogReader
	vault      vaultdomain.Repository
}

// NewPrincipalPreview wires the preview read. vault may be nil (a plane without
// a credential store): connections then report every forwarded-auth source as
// not linked.
func NewPrincipalPreview(
	installs installationdomain.Repository,
	registries RegistryLister,
	catalog CatalogReader,
	vault vaultdomain.Repository,
) (PrincipalPreview, error) {
	if installs == nil || registries == nil || catalog == nil {
		return nil, ErrUnavailable
	}
	return &principalPreview{installs: installs, registries: registries, catalog: catalog, vault: vault}, nil
}

func (p *principalPreview) Preview(ctx context.Context, gatewayID ids.GatewayID, principalSub string) (*PrincipalState, error) {
	principalSub = strings.TrimSpace(principalSub)
	if gatewayID.IsNil() {
		return nil, fmt.Errorf("gateway id is required: %w", commonerrors.ErrValidation)
	}
	if principalSub == "" {
		return nil, fmt.Errorf("principal subject is required: %w", commonerrors.ErrValidation)
	}
	regs, _, err := p.registries.List(ctx, registrydomain.ListFilter{GatewayID: gatewayID, Page: 1, Size: registryListPageSize})
	if err != nil {
		return nil, fmt.Errorf("store: list registries: %w", err)
	}
	byID := make(map[ids.RegistryID]*registrydomain.Registry, len(regs))
	for _, reg := range regs {
		if reg != nil {
			byID[reg.ID] = reg
		}
	}

	installs, err := p.installs.ListByPrincipal(ctx, gatewayID, principalSub)
	if err != nil {
		return nil, fmt.Errorf("store: list installs: %w", err)
	}
	state := &PrincipalState{
		PrincipalSub: principalSub,
		Installs:     make([]PrincipalInstall, 0, len(installs)),
		Connections:  []PrincipalConnection{},
	}
	for _, in := range installs {
		if in == nil {
			continue
		}
		row := PrincipalInstall{
			InstanceID:  in.ID,
			Code:        in.CatalogCode,
			Name:        in.CatalogCode,
			RegistryID:  in.RegistryID,
			Status:      in.Status,
			InstalledBy: in.InstalledBy,
			CreatedAt:   in.CreatedAt,
			UpdatedAt:   in.UpdatedAt,
		}
		if entry, ok := p.catalog.GetByCode(in.CatalogCode); ok && entry.DisplayName != "" {
			row.Name = entry.DisplayName
		}
		if reg := byID[in.RegistryID]; reg != nil {
			row.Registry = reg.Name
		}
		state.Installs = append(state.Installs, row)
	}

	sorted := make([]*registrydomain.Registry, 0, len(regs))
	for _, reg := range regs {
		if reg != nil {
			sorted = append(sorted, reg)
		}
	}
	sortRegistries(sorted)
	for _, reg := range sorted {
		auth := forwardedAuthOf(reg)
		if auth == nil || strings.TrimSpace(auth.Provider) == "" {
			continue
		}
		conn := PrincipalConnection{
			Provider:   auth.Provider,
			Code:       reg.MCPTarget.Code,
			RegistryID: reg.ID,
			Registry:   reg.Name,
		}
		if err := p.fillConnection(ctx, gatewayID, principalSub, &conn); err != nil {
			return nil, err
		}
		state.Connections = append(state.Connections, conn)
	}
	return state, nil
}

// credentialExpiryGrace mirrors the connect flow: a token about to expire with
// no refresh token counts as needing a reconnect.
const credentialExpiryGrace = 60 * time.Second

func (p *principalPreview) fillConnection(ctx context.Context, gatewayID ids.GatewayID, principalSub string, conn *PrincipalConnection) error {
	if p.vault == nil {
		return nil
	}
	cred, err := p.vault.Find(ctx, gatewayID, principalSub, conn.Provider)
	switch {
	case err == nil:
		conn.Linked = true
		conn.AccountRef = cred.AccountRef
		conn.ExpiresAt = cred.ExpiresAt
		conn.NeedsReconnect = cred.RefreshToken == "" && cred.Expired(credentialExpiryGrace)
	case errors.Is(err, vaultdomain.ErrUndecryptable):
		// The credential exists but the vault key rotated: the user must link again.
		conn.Linked = true
		conn.NeedsReconnect = true
	case errors.Is(err, vaultdomain.ErrNotFound):
	default:
		return fmt.Errorf("store: check linked credential %q: %w", conn.Provider, err)
	}
	return nil
}

// forwardedAuthOf returns the registry's auth block when the upstream expects the
// caller's own credential (the "connect your account" sources), else nil.
func forwardedAuthOf(reg *registrydomain.Registry) *registrydomain.MCPAuth {
	if reg == nil || !reg.IsMCP() || reg.MCPTarget == nil || reg.MCPTarget.Auth == nil {
		return nil
	}
	if reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeForwarded {
		return nil
	}
	return reg.MCPTarget.Auth
}
