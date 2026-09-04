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

// Package store holds the MCP Store's application services: installing a
// catalog entry for a principal and scoping the per-principal surface.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// registryListPageSize bounds the per-gateway registry scan used to find the
// shelf registry for a catalog code. Registries per gateway are few (tens).
const registryListPageSize = 500

var (
	ErrUnavailable          = errors.New("store: installer unavailable")
	ErrCatalogEntryNotFound = errors.New("store: catalog entry not found")
	// ErrRoleNotAllowed is returned when a server is on the shelf but the
	// principal's roles are not permitted to install it.
	ErrRoleNotAllowed = errors.New("store: your role is not allowed to install this server")
)

// CatalogReader is the catalog lookup the installer needs.
type CatalogReader interface {
	GetByCode(code string) (catalogdomain.MCPServer, bool)
}

// RegistryLister lists a gateway's registries so the installer/scoper can find
// the shelf registry for a catalog code.
type RegistryLister interface {
	List(ctx context.Context, filter registrydomain.ListFilter) ([]*registrydomain.Registry, int, error)
}

// InstallResult reports the outcome of an install to the caller (the meta-tool).
type InstallResult struct {
	Code   string
	Name   string
	Status installationdomain.Status
	// Pending is true when the install was recorded as a request awaiting
	// approval (server needs approval, or is not on the shelf yet).
	Pending          bool
	RequiresAuth     bool
	AlreadyInstalled bool
}

//go:generate mockery --name=Installer --dir=. --output=./mocks --filename=store_installer_mock.go --case=underscore --with-expecter
type Installer interface {
	Install(ctx context.Context, in InstallRequest) (*InstallResult, error)
	Uninstall(ctx context.Context, gatewayID ids.GatewayID, principalSub, code string) error
}

// InstallRequest carries everything an install decision needs. Groups are the
// caller's IdP groups (from the token), used for role-gated servers.
type InstallRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	InstalledBy  string
	Groups       []string
}

type installer struct {
	catalog    CatalogReader
	registries RegistryLister
	installs   installationdomain.Repository
}

// NewInstaller wires the Store installer. Installing references a shelf registry
// the admin curated (store.available); a server that is not available, or is
// available but marked requires-approval, is recorded as a pending request
// rather than granted. The shared registry is never created here — that is the
// admin's activate/approve path.
func NewInstaller(
	catalog CatalogReader,
	registries RegistryLister,
	installs installationdomain.Repository,
) (Installer, error) {
	if catalog == nil || registries == nil || installs == nil {
		return nil, ErrUnavailable
	}
	return &installer{catalog: catalog, registries: registries, installs: installs}, nil
}

func (i *installer) Install(ctx context.Context, in InstallRequest) (*InstallResult, error) {
	code := strings.TrimSpace(in.Code)
	entry, ok := i.catalog.GetByCode(code)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogEntryNotFound, code)
	}

	reg, err := findRegistryByCode(ctx, i.registries, in.GatewayID, code)
	if err != nil {
		return nil, err
	}

	// TEMP DEBUG: why does an install resolve to pending? Logs the gateway the
	// install runs against, every registry code visible on it in the data-plane
	// snapshot, and the matched registry's Store shelf state.
	if items, _, lerr := i.registries.List(ctx, registrydomain.ListFilter{
		GatewayID: in.GatewayID, Page: 1, Size: registryListPageSize,
	}); lerr == nil {
		codes := make([]string, 0, len(items))
		for _, r := range items {
			if r != nil && r.MCPTarget != nil {
				codes = append(codes, r.MCPTarget.Code)
			}
		}
		var matchedAvailable, matchedApproval bool
		if reg != nil && reg.MCPTarget != nil {
			matchedAvailable = reg.MCPTarget.StoreAvailable()
			matchedApproval = reg.MCPTarget.StoreRequiresApproval()
		}
		slog.Default().Info("TEMP store-install debug",
			slog.String("gateway_id", in.GatewayID.String()),
			slog.String("install_code", code),
			slog.Int("registry_count", len(items)),
			slog.String("registry_codes", strings.Join(codes, ",")),
			slog.Bool("matched", reg != nil),
			slog.Bool("matched_available", matchedAvailable),
			slog.Bool("matched_requires_approval", matchedApproval),
			slog.String("principal_groups", strings.Join(in.Groups, ",")),
		)
	}

	status, err := i.decideStatus(reg, in.Groups)
	if err != nil {
		return nil, err
	}

	existing, err := i.installs.Find(ctx, in.GatewayID, in.PrincipalSub, code)
	if err != nil && !errors.Is(err, installationdomain.ErrNotFound) {
		return nil, err
	}
	alreadyInstalled := err == nil && existing.IsActive()

	record, err := installationForStatus(in.GatewayID, in.PrincipalSub, code, in.InstalledBy, status)
	if err != nil {
		return nil, err
	}
	if err := i.installs.Upsert(ctx, record); err != nil {
		return nil, err
	}

	return &InstallResult{
		Code:             code,
		Name:             displayName(entry, code),
		Status:           status,
		Pending:          status == installationdomain.StatusPendingApproval,
		RequiresAuth:     entry.RequiresAuth,
		AlreadyInstalled: alreadyInstalled,
	}, nil
}

// decideStatus applies the shelf governance: available + role-allowed installs
// immediately unless it needs approval; anything else becomes a pending request.
//
// The role gate is evaluated as soon as a shelf registry exists, before the
// availability check. Otherwise a role-excluded principal could file a pending
// request against a not-yet-available role-gated server (the role list never
// checked), and the approve path — which does not re-evaluate roles — would
// silently grant it. Checking here means such a request is rejected up front and
// never reaches the approval queue.
func (i *installer) decideStatus(
	reg *registrydomain.Registry,
	groups []string,
) (installationdomain.Status, error) {
	if reg == nil || reg.MCPTarget == nil {
		// No shelf registry at all: a request for the admin to shelve+approve.
		// There is no role list to enforce until the admin connects the server.
		return installationdomain.StatusPendingApproval, nil
	}
	if !rolesAllow(reg.MCPTarget.StoreRoles(), groups) {
		return "", ErrRoleNotAllowed
	}
	if !reg.MCPTarget.StoreAvailable() {
		// On record but hidden: a request for the admin to shelve+approve.
		return installationdomain.StatusPendingApproval, nil
	}
	if reg.MCPTarget.StoreRequiresApproval() {
		return installationdomain.StatusPendingApproval, nil
	}
	return installationdomain.StatusInstalled, nil
}

func (i *installer) Uninstall(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code string,
) error {
	return i.installs.Delete(ctx, gatewayID, principalSub, strings.TrimSpace(code))
}

// findRegistryByCode scans a gateway's registries for the shelf registry whose
// mcp_target carries the given catalog code. Returns (nil, nil) when none match.
func findRegistryByCode(
	ctx context.Context,
	lister RegistryLister,
	gatewayID ids.GatewayID,
	code string,
) (*registrydomain.Registry, error) {
	items, _, err := lister.List(ctx, registrydomain.ListFilter{
		GatewayID: gatewayID,
		Page:      1,
		Size:      registryListPageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("store: list registries: %w", err)
	}
	for _, reg := range items {
		if reg != nil && reg.MCPTarget != nil && reg.MCPTarget.Code == code {
			return reg, nil
		}
	}
	return nil, nil
}

// rolesAllow reports whether the caller may install a role-gated server. An
// empty allow-list means any Store-admitted principal.
func rolesAllow(allowed, groups []string) bool {
	if len(allowed) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		set[g] = struct{}{}
	}
	for _, a := range allowed {
		if _, ok := set[a]; ok {
			return true
		}
	}
	return false
}

func installationForStatus(
	gatewayID ids.GatewayID,
	principalSub, code, installedBy string,
	status installationdomain.Status,
) (*installationdomain.Installation, error) {
	in, err := installationdomain.New(gatewayID, principalSub, code, installedBy, nil)
	if err != nil {
		return nil, err
	}
	in.Status = status
	return in, nil
}

func displayName(entry catalogdomain.MCPServer, code string) string {
	if name := strings.TrimSpace(entry.DisplayName); name != "" {
		return name
	}
	return code
}
