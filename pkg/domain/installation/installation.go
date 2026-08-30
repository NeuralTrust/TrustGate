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

// Package installation is the MCP Store's per-principal state: which catalog
// entries a user has installed on a gateway. It is durable and queryable (for
// admin visibility) and lives outside the config-snapshot, like the vault —
// installs scale per user without growing the shared gateway config.
package installation

import (
	"context"
	"fmt"
	"strings"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

var (
	ErrInvalidInstallation = fmt.Errorf("installation: invalid installation: %w", commonerrors.ErrValidation)
	ErrNotFound            = fmt.Errorf("installation: not found: %w", commonerrors.ErrNotFound)
)

// Status is the lifecycle state of a Store installation.
type Status string

const (
	// StatusInstalled: the entry is installed and its tools are on the user's
	// Store surface.
	StatusInstalled Status = "installed"
	// StatusPendingApproval: the user requested a governed entry and an approver
	// has not yet decided; tools are not surfaced.
	StatusPendingApproval Status = "pending_approval"
	// StatusRevoked: the install was withdrawn (by the user or an admin); kept as
	// a row for audit rather than deleted.
	StatusRevoked Status = "revoked"
)

func (s Status) valid() bool {
	switch s {
	case StatusInstalled, StatusPendingApproval, StatusRevoked:
		return true
	default:
		return false
	}
}

// Installation records that a principal has installed one catalog entry on a
// gateway. It intentionally holds no upstream connection detail: the upstream is
// a single shared registry per catalog code, and the user's credentials live in
// the vault. Only a per-user endpoint override (URL variables) belongs here.
type Installation struct {
	ID           ids.InstallationID
	GatewayID    ids.GatewayID
	PrincipalSub string
	CatalogCode  string
	Status       Status
	// InstalledBy is the subject that caused the install: the principal for a
	// self-service install, or an admin/actor for a provisioned one.
	InstalledBy string
	// Config carries optional per-user overrides (e.g. URL variables) that
	// specialise the shared registry for this principal. Nil when the shared
	// registry is used as-is.
	Config    map[string]string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// New builds a fresh installation in the installed state.
func New(
	gatewayID ids.GatewayID,
	principalSub, catalogCode, installedBy string,
	config map[string]string,
) (*Installation, error) {
	return newWithStatus(gatewayID, principalSub, catalogCode, installedBy, StatusInstalled, config)
}

func newWithStatus(
	gatewayID ids.GatewayID,
	principalSub, catalogCode, installedBy string,
	status Status,
	config map[string]string,
) (*Installation, error) {
	if gatewayID.IsNil() {
		return nil, fmt.Errorf("%w: gateway id is required", ErrInvalidInstallation)
	}
	if strings.TrimSpace(principalSub) == "" {
		return nil, fmt.Errorf("%w: principal subject is required", ErrInvalidInstallation)
	}
	if strings.TrimSpace(catalogCode) == "" {
		return nil, fmt.Errorf("%w: catalog code is required", ErrInvalidInstallation)
	}
	if !status.valid() {
		return nil, fmt.Errorf("%w: invalid status %q", ErrInvalidInstallation, status)
	}
	id, err := ids.NewV7[ids.InstallationKind]()
	if err != nil {
		return nil, fmt.Errorf("installation: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	return &Installation{
		ID:           id,
		GatewayID:    gatewayID,
		PrincipalSub: principalSub,
		CatalogCode:  catalogCode,
		Status:       status,
		InstalledBy:  installedBy,
		Config:       config,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// IsActive reports whether the installation currently contributes to the user's
// Store surface.
func (i *Installation) IsActive() bool {
	return i != nil && i.Status == StatusInstalled
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=installation_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	// Upsert creates or updates the installation for (gateway, principal, code).
	Upsert(ctx context.Context, in *Installation) error
	// Find returns the installation for (gateway, principal, code), or ErrNotFound.
	Find(ctx context.Context, gatewayID ids.GatewayID, principalSub, catalogCode string) (*Installation, error)
	// ListByPrincipal returns everything a principal has installed on a gateway —
	// the CatalogScoper's read side.
	ListByPrincipal(ctx context.Context, gatewayID ids.GatewayID, principalSub string) ([]*Installation, error)
	// ListByCatalogCode returns every principal who installed a catalog entry on a
	// gateway — the admin "who installed X" read side.
	ListByCatalogCode(ctx context.Context, gatewayID ids.GatewayID, catalogCode string) ([]*Installation, error)
	// ListPendingByGateway returns every pending-approval request on a gateway,
	// oldest first — the admin approval queue.
	ListPendingByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Installation, error)
	// Delete removes the installation for (gateway, principal, code).
	Delete(ctx context.Context, gatewayID ids.GatewayID, principalSub, catalogCode string) error
}
