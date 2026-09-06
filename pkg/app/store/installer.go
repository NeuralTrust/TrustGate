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
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// registryListPageSize bounds the per-gateway registry scan used to find the
// shelf registry for a catalog code. Registries per gateway are few (tens).
const registryListPageSize = 500

// Instance caps. A principal may legitimately hold a handful of instances of one
// code (several Snowflake schemas) and a few dozen servers overall; anything
// beyond is abuse (request spam, surface bloat) and is refused. Revoked rows do
// not count — they are audit leftovers, not live or queued instances.
const (
	// MaxInstancesPerCode caps live+pending instances of one catalog code per
	// principal on a gateway.
	MaxInstancesPerCode = 10
	// MaxInstancesPerPrincipal caps live+pending instances across all codes per
	// principal on a gateway.
	MaxInstancesPerPrincipal = 100
)

var (
	ErrUnavailable          = errors.New("store: installer unavailable")
	ErrCatalogEntryNotFound = errors.New("store: catalog entry not found")
	// ErrRoleNotAllowed is returned when a server is on the shelf but the
	// principal's roles are not permitted to install it.
	ErrRoleNotAllowed = errors.New("store: your role is not allowed to install this server")
	// ErrConfigInvalid is returned when the per-user configuration supplied with an
	// install is malformed: an unknown variable, an unsafe value, or a secret
	// passed inline (secrets must go through the connect link).
	ErrConfigInvalid = errors.New("store: invalid install configuration")
	// ErrAmbiguousInstance is returned when an uninstall targets a catalog code the
	// principal holds several instances of without naming which one; the caller
	// should list the instances (Instances) and re-issue with an instance id.
	ErrAmbiguousInstance = errors.New("store: multiple instances installed; specify which instance")
	// ErrTooManyInstances is returned when an install would create a new instance
	// beyond MaxInstancesPerCode or MaxInstancesPerPrincipal. It wraps
	// ErrValidation so the HTTP layer maps it to a client error.
	ErrTooManyInstances = fmt.Errorf("store: too many instances installed: %w", commonerrors.ErrValidation)
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
	// InstanceID is the id of the installation row this install recorded or
	// refreshed, so follow-up operations (configure, connect, approve) can target
	// this exact instance rather than "whichever row has this code". Empty when no
	// row was recorded (RequiresConfig / RequiresAdminSetup).
	InstanceID string
	// Pending is true when the install was recorded as a request awaiting
	// approval (server needs approval, or is not on the shelf yet).
	Pending          bool
	RequiresAuth     bool
	AlreadyInstalled bool
	// RequiresConfig is true when the server declares required per-user URL
	// variables the caller has not yet supplied. No install is recorded; the
	// caller collects ConfigVariables and re-invokes with them.
	RequiresConfig  bool
	ConfigVariables []registrydomain.MCPURLVariable
	// RequiresAdminSetup is true when the server cannot be self-served: its only
	// authentication is a shared static credential (an API key header) that the
	// catalog does not carry and only an admin can add on the shelf. No install
	// is recorded and no registry is materialised.
	RequiresAdminSetup bool
}

//go:generate mockery --name=Installer --dir=. --output=./mocks --filename=store_installer_mock.go --case=underscore --with-expecter
type Installer interface {
	Install(ctx context.Context, in InstallRequest) (*InstallResult, error)
	// Instances returns the principal's active instances of a catalog code, so the
	// caller can present a picker when an operation must target one of several.
	Instances(ctx context.Context, gatewayID ids.GatewayID, principalSub, code string) ([]*installationdomain.Installation, error)
	// Uninstall removes an install. When instanceID is set it removes that one
	// instance (which must belong to code); otherwise it removes the sole
	// instance, or returns ErrAmbiguousInstance when the principal holds several
	// of that code.
	Uninstall(ctx context.Context, gatewayID ids.GatewayID, principalSub, code, instanceID string) error
}

// InstallRequest carries everything an install decision needs. Groups are the
// caller's IdP groups (from the token), used for role-gated servers. OpenMode is
// true when the gateway's Store is open (self-service): a catalog server that is
// not yet on the shelf is materialised and installed immediately rather than
// queued for an admin.
type InstallRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	InstalledBy  string
	Groups       []string
	OpenMode     bool
	// Config carries the per-user URL variable values the caller supplied (e.g.
	// {"instance":"acme","database":"analytics"}). Non-secret only — secrets are
	// collected through the connect link, never inline. Validated against the
	// catalog entry's declaration; missing required values yield a RequiresConfig
	// result rather than an install.
	Config map[string]string
}

type installer struct {
	catalog    CatalogReader
	registries RegistryLister
	installs   installationdomain.Repository
	ensurer    RegistryEnsurer
}

// NewInstaller wires the Store installer. In open (self-service) mode a catalog
// server that is not yet on the shelf is materialised through the ensurer and
// installed immediately — the "created on first install" path. In curated mode,
// or when no ensurer is wired, a server that is not on the shelf is recorded as
// a pending request for the admin instead. An on-shelf registry marked
// requires-approval, or one the principal's role excludes, is governed as
// before. ensurer may be nil (SEARCH-only planes, or where materialisation is
// not available); its absence downgrades a self-service install to a request.
func NewInstaller(
	catalog CatalogReader,
	registries RegistryLister,
	installs installationdomain.Repository,
	ensurer RegistryEnsurer,
) (Installer, error) {
	if catalog == nil || registries == nil || installs == nil {
		return nil, ErrUnavailable
	}
	return &installer{catalog: catalog, registries: registries, installs: installs, ensurer: ensurer}, nil
}

func (i *installer) Install(ctx context.Context, in InstallRequest) (*InstallResult, error) {
	code := strings.TrimSpace(in.Code)
	entry, ok := i.catalog.GetByCode(code)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogEntryNotFound, code)
	}

	// Per-user endpoint configuration (URL variables). Reject malformed input.
	// Plain values can be supplied inline; missing required plain values stop the
	// install and are reported for the caller to collect (inline or via the form).
	// Secret values are never inline — they are entered through the hosted form —
	// so their presence does not block recording the install; the install stands
	// and the dial fails closed until the secret is provided.
	config, missingPlain, secretRequired, err := planInstallConfig(entry, in.Config)
	if err != nil {
		return nil, err
	}
	if len(missingPlain) > 0 {
		return &InstallResult{
			Code:            code,
			Name:            displayName(entry, code),
			RequiresConfig:  true,
			RequiresAuth:    entry.RequiresAuth,
			ConfigVariables: missingPlain,
		}, nil
	}

	// A principal may hold several instances of one code. An install with config
	// identical to an existing instance is that same instance (idempotent: refresh
	// it in place); a new config is a new instance (a fresh row/id) — subject to
	// the instance caps, checked before any side effect (materialisation).
	existing, err := i.installs.ListByPrincipalAndCode(ctx, in.GatewayID, in.PrincipalSub, code)
	if err != nil {
		return nil, err
	}
	var sameInstance *installationdomain.Installation
	for _, e := range existing {
		if e.SameConfig(config) {
			sameInstance = e
			break
		}
	}
	if sameInstance == nil {
		if err := i.checkInstanceCaps(ctx, in.GatewayID, in.PrincipalSub, existing); err != nil {
			return nil, err
		}
	}
	alreadyInstalled := sameInstance != nil && sameInstance.IsActive()

	reg, err := findRegistryByCode(ctx, i.registries, in.GatewayID, code)
	if err != nil {
		return nil, err
	}

	// Self-service cannot conjure a shared API key: a server whose only auth is a
	// static header credential has nothing the catalog can materialise (the
	// registry would fail validation with an empty value). Report it cleanly and
	// leave both the shelf and the install table untouched — an admin connects it
	// with the key, after which it installs like any shelved server.
	if reg == nil && in.OpenMode && i.ensurer != nil && catalogNeedsAdminCredential(entry) {
		return &InstallResult{
			Code:               code,
			Name:               displayName(entry, code),
			RequiresAuth:       entry.RequiresAuth,
			RequiresAdminSetup: true,
		}, nil
	}

	status, err := i.decideStatus(ctx, in, reg)
	if err != nil {
		return nil, err
	}

	record, err := installationForStatus(in.GatewayID, in.PrincipalSub, code, in.InstalledBy, status, config)
	if err != nil {
		return nil, err
	}
	// Reuse the existing instance's id so a repeat install updates it in place
	// rather than inserting a duplicate; a new-config install keeps its fresh id.
	if sameInstance != nil {
		record.ID = sameInstance.ID
		record.CreatedAt = sameInstance.CreatedAt
	}
	if err := i.installs.Upsert(ctx, record); err != nil {
		return nil, err
	}

	result := &InstallResult{
		Code:             code,
		Name:             displayName(entry, code),
		Status:           status,
		InstanceID:       record.ID.String(),
		Pending:          status == installationdomain.StatusPendingApproval,
		RequiresAuth:     entry.RequiresAuth,
		AlreadyInstalled: alreadyInstalled,
	}
	// The install is recorded, but its tools stay dark until the user enters the
	// required secret(s) at the hosted form.
	if len(secretRequired) > 0 {
		result.RequiresConfig = true
		result.ConfigVariables = secretRequired
	}
	return result, nil
}

// checkInstanceCaps refuses a would-be new instance when the principal already
// holds MaxInstancesPerCode live-or-pending instances of this code, or
// MaxInstancesPerPrincipal across the gateway. existing is the principal's rows
// for the code (already loaded by the caller).
func (i *installer) checkInstanceCaps(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	existing []*installationdomain.Installation,
) error {
	if countLive(existing) >= MaxInstancesPerCode {
		return fmt.Errorf("%w: at most %d instances of one server", ErrTooManyInstances, MaxInstancesPerCode)
	}
	all, err := i.installs.ListByPrincipal(ctx, gatewayID, principalSub)
	if err != nil {
		return err
	}
	if countLive(all) >= MaxInstancesPerPrincipal {
		return fmt.Errorf("%w: at most %d installed servers", ErrTooManyInstances, MaxInstancesPerPrincipal)
	}
	return nil
}

// countLive counts rows that occupy a slot: installed or pending. Revoked rows
// are audit leftovers and do not count.
func countLive(rows []*installationdomain.Installation) int {
	n := 0
	for _, r := range rows {
		if r != nil && r.Status != installationdomain.StatusRevoked {
			n++
		}
	}
	return n
}

// planInstallConfig validates the caller's supplied URL-variable values against
// the catalog entry's declaration and partitions what is still needed. It rejects
// malformed input (unknown variable, unsafe value, or a secret supplied inline).
// It returns: the plain values to persist on the installation; the required plain
// variables still missing (which block the install until supplied); and the
// required secret variables (collected out-of-band through the hosted form, so
// they do not block recording the install).
func planInstallConfig(
	entry catalogdomain.MCPServer,
	provided map[string]string,
) (config map[string]string, missingPlain, secretRequired []registrydomain.MCPURLVariable, err error) {
	declared := catalogURLVariables(entry.URLVariables)
	if len(declared) == 0 {
		return nil, nil, nil, nil
	}
	byName := make(map[string]registrydomain.MCPURLVariable, len(declared))
	for _, v := range declared {
		byName[v.Name] = v
	}
	stored := make(map[string]string, len(provided))
	for k, raw := range provided {
		val := strings.TrimSpace(raw)
		if val == "" {
			continue
		}
		v, known := byName[k]
		if !known {
			return nil, nil, nil, fmt.Errorf("%w: unknown variable %q", ErrConfigInvalid, k)
		}
		if v.Secret {
			return nil, nil, nil, fmt.Errorf("%w: %q is a secret and must be set through the configure form, not inline", ErrConfigInvalid, k)
		}
		if err := registrydomain.ValidateURLValue(v, val); err != nil {
			return nil, nil, nil, fmt.Errorf("%w: %w", ErrConfigInvalid, err)
		}
		stored[k] = val
	}
	for _, v := range declared {
		if !v.Required {
			continue
		}
		switch {
		case v.Secret:
			secretRequired = append(secretRequired, v)
		case strings.TrimSpace(stored[v.Name]) == "":
			missingPlain = append(missingPlain, v)
		}
	}
	if len(stored) == 0 {
		stored = nil
	}
	return stored, missingPlain, secretRequired, nil
}

// decideStatus applies the shelf governance: available + role-allowed installs
// immediately unless it needs approval; anything else becomes a pending request.
//
// When no shelf registry exists yet the decision splits on the Store mode. In
// open (self-service) mode the shared registry is materialised from the catalog
// here and the install proceeds immediately — the "created on first install"
// path; the fresh registry is available with no roles or approval, so it is
// governed identically on the next install. In curated mode (or when no ensurer
// is wired) the same missing-registry case is a pending request for the admin to
// shelve+approve, exactly as before.
//
// The role gate is evaluated as soon as a shelf registry exists, before the
// availability check. Otherwise a role-excluded principal could file a pending
// request against a not-yet-available role-gated server (the role list never
// checked), and the approve path — which does not re-evaluate roles — would
// silently grant it. Checking here means such a request is rejected up front and
// never reaches the approval queue.
func (i *installer) decideStatus(
	ctx context.Context,
	in InstallRequest,
	reg *registrydomain.Registry,
) (installationdomain.Status, error) {
	if reg == nil || reg.MCPTarget == nil {
		// No shelf registry at all. Self-service materialises it on first
		// install; otherwise it is a request for the admin to shelve+approve.
		// There is no role list to enforce until the registry exists.
		if in.OpenMode && i.ensurer != nil {
			if err := i.ensurer.Ensure(ctx, in.GatewayID, in.Code); err != nil {
				return "", err
			}
			return installationdomain.StatusInstalled, nil
		}
		return installationdomain.StatusPendingApproval, nil
	}
	if !storeAccessAllows(reg.MCPTarget.StoreGroups(), reg.MCPTarget.StoreUsers(), in.Groups, in.PrincipalSub) {
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

// Instances returns the principal's active instances of a catalog code, oldest
// first, for a disambiguation picker.
func (i *installer) Instances(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code string,
) ([]*installationdomain.Installation, error) {
	all, err := i.installs.ListByPrincipalAndCode(ctx, gatewayID, principalSub, strings.TrimSpace(code))
	if err != nil {
		return nil, err
	}
	active := make([]*installationdomain.Installation, 0, len(all))
	for _, in := range all {
		if in.IsActive() {
			active = append(active, in)
		}
	}
	return active, nil
}

func (i *installer) Uninstall(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code, instanceID string,
) error {
	code = strings.TrimSpace(code)
	// A specific instance was named: remove exactly that one — and only if it is
	// an instance of the named code, so a stray id cannot be used to revoke an
	// unrelated server.
	if id := strings.TrimSpace(instanceID); id != "" {
		installID, err := ids.Parse[ids.InstallationKind](id)
		if err != nil {
			return fmt.Errorf("%w: invalid instance id %q", installationdomain.ErrInvalidInstallation, id)
		}
		target, err := i.installs.FindByID(ctx, gatewayID, principalSub, installID)
		if err != nil {
			return err
		}
		if target.CatalogCode != code {
			return fmt.Errorf("%w: instance %q is not an instance of %q", installationdomain.ErrNotFound, id, code)
		}
		return i.installs.DeleteByID(ctx, gatewayID, principalSub, installID)
	}
	// Otherwise remove the sole instance; refuse to guess when several exist.
	active, err := i.Instances(ctx, gatewayID, principalSub, code)
	if err != nil {
		return err
	}
	switch len(active) {
	case 0:
		// Nothing active; fall back to clearing any inactive row for the code.
		return i.installs.Delete(ctx, gatewayID, principalSub, code)
	case 1:
		return i.installs.DeleteByID(ctx, gatewayID, principalSub, active[0].ID)
	default:
		return ErrAmbiguousInstance
	}
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

// storeAccessAllows reports whether the caller may install a subject-gated
// server. The grant has two axes: allowedGroups (matched against the caller's
// group claim) and allowedUsers (matched against the caller's subject). When
// both are empty the server is open to any Store-admitted principal; otherwise
// the caller is allowed if their groups intersect allowedGroups OR their subject
// is in allowedUsers.
func storeAccessAllows(allowedGroups, allowedUsers, groups []string, subject string) bool {
	if len(allowedGroups) == 0 && len(allowedUsers) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		set[g] = struct{}{}
	}
	for _, a := range allowedGroups {
		if _, ok := set[a]; ok {
			return true
		}
	}
	sub := strings.TrimSpace(subject)
	if sub != "" {
		for _, u := range allowedUsers {
			if strings.TrimSpace(u) == sub {
				return true
			}
		}
	}
	return false
}

func installationForStatus(
	gatewayID ids.GatewayID,
	principalSub, code, installedBy string,
	status installationdomain.Status,
	config map[string]string,
) (*installationdomain.Installation, error) {
	in, err := installationdomain.New(gatewayID, principalSub, code, installedBy, config)
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
