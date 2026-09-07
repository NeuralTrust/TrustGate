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
	"sort"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

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
	// ErrUnknownInstance is returned when an install names a configured instance
	// (registry) that does not exist on the gateway or is not an instance of the
	// requested catalog code.
	ErrUnknownInstance = fmt.Errorf("store: unknown server instance: %w", commonerrors.ErrValidation)
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
	// RequiresInstanceChoice is true when the admin has connected several
	// instances of this server that the principal may use and the install did not
	// say which. No install is recorded; the caller picks one of InstanceChoices
	// and re-invokes with its id.
	RequiresInstanceChoice bool
	InstanceChoices        []InstanceChoice
}

// InstanceChoice is one configured instance (registry) of a catalog code the
// principal may install.
type InstanceChoice struct {
	RegistryID ids.RegistryID
	Name       string
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
	// RegistryID names the configured instance to install when the admin has
	// connected several of this code (from a prior RequiresInstanceChoice
	// result). Nil lets the installer pick: the sole usable instance, or the one
	// materialised from the catalog.
	RegistryID ids.RegistryID
}

type installer struct {
	catalog    CatalogReader
	registries RegistryLister
	installs   installationdomain.Repository
	grants     storeaccessdomain.Reader
	ensurer    RegistryEnsurer
}

// NewInstaller wires the Store installer over the catalog, the gateway's
// registries (its configured instances), the installation rows, the Store
// access grants and the registry materialiser.
//
// grants is the access model: under Selected access a principal installs what
// the grants name for them (a catalog code, or one instance of it) instantly and
// requests anything else. It may be nil on a plane without grants, which fails
// closed (nothing is granted). ensurer materialises a registry from the catalog
// on the first install of a code nobody connected yet — the self-service path
// under All, and the lazy path for a code-level grant under Selected; nil
// downgrades those installs to requests.
func NewInstaller(
	catalog CatalogReader,
	registries RegistryLister,
	installs installationdomain.Repository,
	grants storeaccessdomain.Reader,
	ensurer RegistryEnsurer,
) (Installer, error) {
	if catalog == nil || registries == nil || installs == nil {
		return nil, ErrUnavailable
	}
	return &installer{
		catalog:    catalog,
		registries: registries,
		installs:   installs,
		grants:     grants,
		ensurer:    ensurer,
	}, nil
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

	// Which configured instance (registry) does this install bind to, and does it
	// install now or file a request? Decided against the gateway's instances of
	// the code and the principal's grants, before any row is touched.
	decision, err := i.decide(ctx, in, entry, code)
	if err != nil {
		return nil, err
	}
	if decision.requiresAdminSetup {
		return &InstallResult{
			Code:               code,
			Name:               displayName(entry, code),
			RequiresAuth:       entry.RequiresAuth,
			RequiresAdminSetup: true,
		}, nil
	}
	if len(decision.choices) > 0 {
		return &InstallResult{
			Code:                   code,
			Name:                   displayName(entry, code),
			RequiresAuth:           entry.RequiresAuth,
			RequiresInstanceChoice: true,
			InstanceChoices:        decision.choices,
		}, nil
	}

	// A principal may hold several instances of one code. An install bound to the
	// same configured instance with identical config is that same instance
	// (idempotent: refresh it in place); anything else is a new instance (a fresh
	// row/id) — subject to the instance caps, checked before any side effect.
	existing, err := i.installs.ListByPrincipalAndCode(ctx, in.GatewayID, in.PrincipalSub, code)
	if err != nil {
		return nil, err
	}
	var sameInstance *installationdomain.Installation
	for _, e := range existing {
		if e.SameInstance(decision.registryID, config) {
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

	// Materialise the registry only once the install is certain to be recorded.
	if decision.materialise {
		if err := i.ensurer.Ensure(ctx, in.GatewayID, code); err != nil {
			return nil, err
		}
	}

	record, err := installationForStatus(in.GatewayID, in.PrincipalSub, code, in.InstalledBy, decision.status, config)
	if err != nil {
		return nil, err
	}
	record.RegistryID = decision.registryID
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
		Status:           decision.status,
		InstanceID:       record.ID.String(),
		Pending:          decision.status == installationdomain.StatusPendingApproval,
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

// installDecision is the outcome of applying the Store access model to one
// install request: which configured instance it binds to (nil = the code's
// canonical instance), whether it installs now or files a request, whether the
// registry must first be materialised from the catalog, or — instead of
// recording anything — that the caller must pick among several instances or
// that an admin must connect the server first.
type installDecision struct {
	registryID         ids.RegistryID
	status             installationdomain.Status
	materialise        bool
	choices            []InstanceChoice
	requiresAdminSetup bool
}

// decide applies the Store access model:
//
//   - All (open): every catalog server installs instantly. With several
//     configured instances the caller must pick one; with none the registry is
//     materialised from the catalog on first install (when an ensurer is wired;
//     otherwise the install can only be recorded as a request).
//   - Selected (curated): what the grants name for the principal installs
//     instantly — a code-level grant covers every instance of the code (and
//     materialises it when none exists yet); an instance-level grant covers that
//     one registry. Anything else becomes an approval request for the admin, who
//     grants it by approving. Grants are explicit: nothing named means nothing
//     granted.
//
// A server whose only credential is a shared secret the catalog does not carry
// (an API key header) cannot be materialised by self-service: an admin connects
// it first. There is no per-registry "requires approval" gate: the grant is the
// pre-approval, so Approvals only holds requests for what is not granted.
func (i *installer) decide(
	ctx context.Context,
	in InstallRequest,
	entry catalogdomain.MCPServer,
	code string,
) (installDecision, error) {
	instances, err := findRegistriesByCode(ctx, i.registries, in.GatewayID, code)
	if err != nil {
		return installDecision{}, err
	}
	grants, err := i.grantSet(ctx, in.GatewayID)
	if err != nil {
		return installDecision{}, err
	}
	codeGranted := in.OpenMode || grants.CodeAllows(code, in.Groups, in.PrincipalSub)

	// An explicitly named instance must exist and be an instance of this code.
	if !in.RegistryID.IsNil() {
		reg := pickRegistry(instances, in.RegistryID)
		if reg == nil {
			return installDecision{}, fmt.Errorf("%w: %q is not an instance of %q", ErrUnknownInstance, in.RegistryID, code)
		}
		if codeGranted || grants.Instance(reg.ID).Allows(in.Groups, in.PrincipalSub) {
			return installDecision{registryID: reg.ID, status: installationdomain.StatusInstalled}, nil
		}
		return installDecision{registryID: reg.ID, status: installationdomain.StatusPendingApproval}, nil
	}

	// No instance connected yet: materialise it for whoever holds the code (All,
	// or a code-level grant), otherwise file a code-level request.
	if len(instances) == 0 {
		if !codeGranted {
			return installDecision{status: installationdomain.StatusPendingApproval}, nil
		}
		if i.ensurer == nil {
			return installDecision{status: installationdomain.StatusPendingApproval}, nil
		}
		if catalogNeedsAdminCredential(entry) {
			return installDecision{requiresAdminSetup: true}, nil
		}
		return installDecision{status: installationdomain.StatusInstalled, materialise: true}, nil
	}

	// Instances exist: the usable ones are all of them for a code holder, else
	// those granted individually.
	usable := instances
	if !codeGranted {
		usable = usable[:0:0]
		for _, reg := range instances {
			if grants.Instance(reg.ID).Allows(in.Groups, in.PrincipalSub) {
				usable = append(usable, reg)
			}
		}
	}
	switch len(usable) {
	case 0:
		// Nothing usable: request the code (one instance → bind the request to it
		// so approving grants exactly that instance; several → a code-level
		// request the admin resolves by granting the code or an instance).
		d := installDecision{status: installationdomain.StatusPendingApproval}
		if len(instances) == 1 {
			d.registryID = instances[0].ID
		}
		return d, nil
	case 1:
		// The sole usable instance. When it is also the code's only instance it is
		// the canonical one: leave the binding implicit so the install follows the
		// registry (a re-materialised one included) rather than a stale id.
		d := installDecision{status: installationdomain.StatusInstalled}
		if len(instances) > 1 {
			d.registryID = usable[0].ID
		}
		return d, nil
	default:
		choices := make([]InstanceChoice, 0, len(usable))
		for _, reg := range usable {
			choices = append(choices, InstanceChoice{RegistryID: reg.ID, Name: registryLabel(reg)})
		}
		return installDecision{choices: choices}, nil
	}
}

// grantSet loads and indexes the gateway's Store grants. A plane without a
// grant reader has no grants: fail closed.
func (i *installer) grantSet(ctx context.Context, gatewayID ids.GatewayID) (*storeaccessdomain.Set, error) {
	return loadGrantSet(ctx, i.grants, gatewayID)
}

// loadGrantSet is the shared grant-loading step of the installer, scoper and
// approver: index the gateway's grants, or an empty set when no reader is wired.
func loadGrantSet(ctx context.Context, reader storeaccessdomain.Reader, gatewayID ids.GatewayID) (*storeaccessdomain.Set, error) {
	if reader == nil {
		return storeaccessdomain.Index(nil), nil
	}
	grants, err := reader.ListByGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}
	return storeaccessdomain.Index(grants), nil
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

// sortRegistries orders instances deterministically: creation time, then id.
func sortRegistries(regs []*registrydomain.Registry) {
	sort.SliceStable(regs, func(a, b int) bool {
		if !regs[a].CreatedAt.Equal(regs[b].CreatedAt) {
			return regs[a].CreatedAt.Before(regs[b].CreatedAt)
		}
		return regs[a].ID.String() < regs[b].ID.String()
	})
}

// pickRegistry returns the instance with the given id, or nil.
func pickRegistry(regs []*registrydomain.Registry, id ids.RegistryID) *registrydomain.Registry {
	for _, reg := range regs {
		if reg != nil && reg.ID == id {
			return reg
		}
	}
	return nil
}

// registryLabel is the operator-facing name of a configured instance.
func registryLabel(reg *registrydomain.Registry) string {
	if reg == nil {
		return ""
	}
	if name := strings.TrimSpace(reg.Name); name != "" {
		return name
	}
	if reg.MCPTarget != nil {
		return reg.MCPTarget.Code
	}
	return reg.ID.String()
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
