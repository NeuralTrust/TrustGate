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
	"sort"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

var (
	ErrUnavailable          = errors.New("store: installer unavailable")
	ErrCatalogEntryNotFound = errors.New("store: catalog entry not found")
	// ErrNotInstalled: the principal holds no installed instance of the code
	// (or of the instance named), or holds several and named none.
	ErrNotInstalled = errors.New("store: not installed")
	// ErrNothingInstalled is uninstall of a code the principal has no row for.
	// Removing nothing is an idempotent answer, not a fault in the gateway.
	ErrNothingInstalled = errors.New("store: nothing installed")
	// ErrSSEUnsupported is an install of a catalog server whose only transport
	// is SSE. The gateway dials streamable HTTP and has no SSE client; the
	// install stops before a registry is materialised.
	ErrSSEUnsupported = errors.New("SSE transport is not supported by the gateway yet")
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
	// ErrReasonRequired is returned when an install would become a request and
	// carries no reason. A request is decided by a person, and the reason is the
	// only thing the requester tells them; a queue of reasonless requests is a
	// queue an approver cannot triage. An install that needs no approval is
	// unaffected — it asks nobody, so it needs no reason.
	ErrReasonRequired = fmt.Errorf(
		"store: a request needs a reason for the approver to decide on: %w", commonerrors.ErrValidation,
	)

	// ErrUnknownInstance is returned when an install names a configured instance
	// (registry) that does not exist on the gateway or is not an instance of the
	// requested catalog code.
	ErrUnknownInstance = fmt.Errorf("store: unknown server instance: %w", commonerrors.ErrValidation)

	// ErrServerDisabled is returned when an install names a server, or an instance
	// of it, that an administrator turned off on the gateway.
	ErrServerDisabled = fmt.Errorf("store: an administrator turned this server off on this gateway: %w", commonerrors.ErrConflict)
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
	// RegistryID is the configured instance (registry) the install is bound to,
	// which is what a connect link pins: the account belongs to the server, not
	// to the installation row. Nil when the binding is implicit (the code's only
	// instance), where the code alone names the server.
	RegistryID ids.RegistryID
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
	// say which. An instance whose required admin URL variable is still unfilled
	// is omitted. No install is recorded; the caller picks one of InstanceChoices
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
	// Installed answers an install of a server the principal already has,
	// without writing anything or deciding access again: the instance they
	// hold, as an install result. ErrNotInstalled when there is no single
	// such instance. Store access None does not use it: that mode refuses
	// the install tool before a connect link is minted.
	Installed(ctx context.Context, in InstallRequest) (*InstallResult, error)
	// Uninstall removes an install. When instanceID is set it removes that one
	// instance (which must belong to code); otherwise it removes the sole
	// instance, or returns ErrAmbiguousInstance when the principal holds several
	// of that code. When credentials are wired, removing the last active
	// installation that uses a per-user vault key also deletes that credential.
	// ErrNothingInstalled when the principal has no row for the code.
	Uninstall(ctx context.Context, gatewayID ids.GatewayID, principalSub, code, instanceID string) error
	// InstalledCodes is the set of catalog codes the principal has an active
	// install of. A lookup failure is returned to the caller; search treats that
	// as "unknown" and does not fail the browse.
	InstalledCodes(ctx context.Context, gatewayID ids.GatewayID, principalSub string) (map[string]struct{}, error)
	// PinTarget is the configured instance Install would bind in to. Nil when
	// that install would not resolve to exactly one instance, so a caller
	// leaves every catalog variable per-user.
	PinTarget(ctx context.Context, in InstallRequest) (*registrydomain.MCPTarget, error)
}

// CredentialRevoker revokes the upstream OAuth token held in a per-user
// credential. A nil error means the token was revoked or the provider does not
// advertise revocation. Callers log a non-nil error and still delete the local
// credential.
type CredentialRevoker interface {
	Revoke(ctx context.Context, gatewayID ids.GatewayID, principalSub string, reg *registrydomain.Registry, cred *vaultdomain.Credential) error
}

// InstallerOption configures optional installer dependencies.
type InstallerOption func(*installer)

// WithUninstallCredentials releases the principal's per-user vault credential
// when Uninstall removes the last active installation that resolves to it. A
// shared account is left in place, and so is a credential another active
// installation of the same principal still uses. An admin-provisioned registry
// (any origin other than the store) that resolves to the same per-user key
// keeps it too: that registry reads the vault directly, with no installation
// row. Vault ErrNotFound is success. Any other vault error fails Uninstall
// before the installation row is removed, so a retry can still release the
// credential. Vendor revocation runs only after that local delete and after
// the per-key lock is released. It is best-effort: a failure or an unsupported
// provider is logged and never keeps the local token or fails Uninstall.
// A pinned registry (authorize and token URLs both configured) does not
// revoke; the registry has no revocation URL.
// revoker may be nil, which skips the vendor call. The cached dynamic client
// is not deleted.
// WithCatalogInstanceRefresh asks Ensure to reconcile an existing instance
// with the current catalog, then answers this install from that shape so
// RequiresAuth follows a mode change (for example none to forwarded). The
// reconciler leaves credentials, admin edits, and uncertain rows untouched.
// Ensure errors are logged and do not fail the install.
func WithCatalogInstanceRefresh(viewer CatalogViewer) InstallerOption {
	return func(i *installer) {
		i.viewer = viewer
	}
}

func WithUninstallCredentials(vault vaultdomain.Repository, revoker CredentialRevoker, logger *slog.Logger) InstallerOption {
	return func(i *installer) {
		i.vault = vault
		i.revoker = revoker
		if logger != nil {
			i.logger = logger
		}
	}
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
	// GroupScoped marks a request made with a group key: grants are matched
	// on Groups (the key's group) alone, never on PrincipalSub, which still
	// owns the install.
	GroupScoped bool
	OpenMode    bool
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
	// Reason is why the user wants this server, in their own words. It is kept
	// only on a request an approver has to decide, which is the one place it is
	// read (Access → Approvals); an install that needs no approval asks nobody,
	// so it carries none even when the caller sends one.
	Reason string
}

// grantSubject is the subject a grant may name the requester by: none for a
// group key, whose group alone is granted.
func (in InstallRequest) grantSubject() string {
	if in.GroupScoped {
		return ""
	}
	return in.PrincipalSub
}

type installer struct {
	catalog    CatalogReader
	registries RegistryLister
	installs   installationdomain.Repository
	grants     storeaccessdomain.Reader
	ensurer    RegistryEnsurer
	viewer     CatalogViewer
	vault      vaultdomain.Repository
	revoker    CredentialRevoker
	logger     *slog.Logger
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
	opts ...InstallerOption,
) (Installer, error) {
	if catalog == nil || registries == nil || installs == nil {
		return nil, ErrUnavailable
	}
	inst := &installer{
		catalog:    catalog,
		registries: registries,
		installs:   installs,
		grants:     grants,
		ensurer:    ensurer,
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(inst)
		}
	}
	return inst, nil
}

func (i *installer) Install(ctx context.Context, in InstallRequest) (*InstallResult, error) {
	code := strings.TrimSpace(in.Code)
	entry, ok, err := storeEntry(ctx, i.catalog, i.registries, in.GatewayID, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogEntryNotFound, code)
	}

	// Which configured instance (registry) does this install bind to, and does it
	// install now or file a request? Decided against the gateway's instances of
	// the code and the principal's grants, before any row is touched.
	decision, err := i.decide(ctx, in, entry, code)
	if err != nil {
		return nil, err
	}

	// Per-user endpoint configuration (URL variables). Malformed input is refused
	// here; what is *missing* is held until the access decision is known, because
	// only an install needs it (see below). Secret values are never inline — they
	// are entered through the hosted form — so their absence never blocks
	// recording: the install stands and the dial fails closed until they arrive.
	// Variables the bound instance's URL already fixes are neither asked for nor
	// kept: the dial uses that URL whatever the user sends.
	config, missingPlain, secretRequired, err := planInstallConfig(entry, in.Config, boundTarget(decision.bound))
	if err != nil {
		return nil, err
	}
	// A choice or a request has not picked the row it will dial. The admin URL
	// is required only when this call records an install against one instance.
	// A non-self-service server whose existing row still has that placeholder
	// is the same state as no row: report admin setup and leave the row alone.
	if len(decision.choices) == 0 && !decision.requiresAdminSetup &&
		decision.status != installationdomain.StatusPendingApproval {
		if err := rejectUnfilledAdminVariables(entry.URL, catalogURLVariables(entry.URLVariables), boundTarget(decision.bound)); err != nil {
			if catalogNeedsAdminCredential(entry) {
				return &InstallResult{
					Code:               code,
					Name:               displayName(entry, code),
					RequiresAuth:       entry.RequiresAuth,
					RequiresAdminSetup: true,
				}, nil
			}
			return nil, err
		}
	}
	i.refreshBoundCatalog(ctx, in.GatewayID, code, &decision)
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
	// Refused before anything is recorded: a request filed without a reason
	// cannot be triaged, and the caller can still ask the user and retry.
	if decision.status == installationdomain.StatusPendingApproval &&
		strings.TrimSpace(in.Reason) == "" {
		return nil, ErrReasonRequired
	}
	// Missing per-user endpoint values stop an install, never a request. A
	// request asks an approver whether the user may have the server at all, and
	// their own account URL or database name has no bearing on that answer —
	// asked first, it stopped the request from ever being filed, so a server with
	// required variables could not be requested at all: the caller was told to
	// finish the setup while nothing had been recorded and no approver ever saw
	// it. The values are collected when the approved install is made.
	if len(missingPlain) > 0 && decision.status != installationdomain.StatusPendingApproval {
		return &InstallResult{
			Code:            code,
			Name:            displayName(entry, code),
			RequiresConfig:  true,
			RequiresAuth:    requiresUserAuth(entry, decision.bound),
			ConfigVariables: missingPlain,
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
	// Older data can hold one instance in several rows. Refresh the installed
	// one: refreshing a pending or revoked sibling instead would make the
	// principal hold the installed instance twice.
	//
	// A row written before the bound URL fixed a variable still stores that
	// key. The dial no longer reads it, so it is not what makes an instance.
	bound := boundTarget(decision.bound)
	var sameInstance *installationdomain.Installation
	for _, e := range existing {
		if !sameInstanceIgnoringPins(e, decision.registryID, decision.canonical, config, bound) {
			continue
		}
		if sameInstance == nil || refreshRank(e) < refreshRank(sameInstance) {
			sameInstance = e
		}
	}
	alreadyInstalled := sameInstance != nil && sameInstance.IsActive()

	// Materialise the registry only once the install is certain to be recorded.
	if decision.materialise {
		// SSE is the one catalog transport the gateway cannot dial. Refuse it
		// here, before Ensure, so the failure is this sentence rather than a
		// registry-validation error, and so a registry that already exists is
		// left alone.
		if strings.EqualFold(strings.TrimSpace(entry.Transport), "sse") {
			return nil, ErrSSEUnsupported
		}
		if err := i.ensurer.Ensure(ctx, in.GatewayID, code); err != nil {
			return nil, err
		}
	}

	record, err := installationForStatus(in.GatewayID, in.PrincipalSub, code, in.InstalledBy, decision.status, config)
	if err != nil {
		return nil, err
	}
	record.RegistryID = decision.registryID
	if decision.status == installationdomain.StatusPendingApproval {
		record.Reason = strings.TrimSpace(in.Reason)
		// Kept with the request so the approval can be checked against the groups
		// the requester actually carried (see Installation.RequesterGroups).
		record.RequesterGroups = append([]string(nil), in.Groups...)
	}
	// Reuse the existing instance's id so a repeat install updates it in place
	// rather than inserting a duplicate; a new-config install keeps its fresh id.
	// Its binding is kept too: the upsert finds the row by it.
	if sameInstance != nil {
		record.ID = sameInstance.ID
		record.CreatedAt = sameInstance.CreatedAt
		record.RegistryID = sameInstance.RegistryID
		// The new config omits keys this instance pins. The row already has
		// them, and dropping one changes what a later token refresh asks for.
		record.Config = mergePinnedConfig(record.Config, sameInstance.Config, bound)
	}
	if err := i.installs.Upsert(ctx, record); err != nil {
		return nil, err
	}

	result := &InstallResult{
		Code:             code,
		Name:             displayName(entry, code),
		Status:           decision.status,
		InstanceID:       record.ID.String(),
		RegistryID:       decision.registryID,
		Pending:          decision.status == installationdomain.StatusPendingApproval,
		RequiresAuth:     requiresUserAuth(entry, decision.bound),
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

func refreshRank(in *installationdomain.Installation) int {
	switch in.Status {
	case installationdomain.StatusInstalled:
		return 0
	case installationdomain.StatusPendingApproval:
		return 1
	default:
		return 2
	}
}

// planInstallConfig validates the caller's supplied URL-variable values against
// the catalog entry's declaration and partitions what is still needed. It rejects
// malformed input (unknown variable, unsafe value, or a secret supplied inline).
// It returns: the plain values to persist on the installation; the required plain
// variables still missing (which block the install until supplied); and the
// required secret variables (collected out-of-band through the hosted form, so
// they do not block recording the install). A variable bound pins is dropped
// from all three: its value is never validated, stored or requested.
func planInstallConfig(
	entry catalogdomain.MCPServer,
	provided map[string]string,
	bound *registrydomain.MCPTarget,
) (config map[string]string, missingPlain, secretRequired []registrydomain.MCPURLVariable, err error) {
	all := catalogURLVariables(entry.URLVariables)
	if err := rejectSuppliedNonSecrets(all, provided); err != nil {
		return nil, nil, nil, err
	}
	declared := unpinnedURLVariables(all, bound)
	pinned := make(map[string]struct{})
	for _, v := range entry.URLVariables {
		if bound.PinsURLVariable(v.Name) {
			pinned[strings.TrimSpace(v.Name)] = struct{}{}
		}
	}
	if len(declared) == 0 && len(pinned) == 0 {
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
		if _, ok := pinned[k]; ok {
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
		if !v.Required || !v.Secret {
			continue
		}
		secretRequired = append(secretRequired, v)
	}
	if len(stored) == 0 {
		stored = nil
	}
	return stored, missingPlain, secretRequired, nil
}

// rejectSuppliedNonSecrets refuses a non-secret registry variable from the
// caller. The value belongs on the registry row. A secret credential is the
// caller's own and is not refused here.
func rejectSuppliedNonSecrets(declared []registrydomain.MCPURLVariable, provided map[string]string) error {
	byName := make(map[string]registrydomain.MCPURLVariable, len(declared))
	for _, variable := range declared {
		byName[variable.Name] = variable
	}
	for name, raw := range provided {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		variable, known := byName[name]
		if !known || variable.Secret {
			continue
		}
		return fmt.Errorf("%w: variable %q is set by an admin on the registry", ErrConfigInvalid, name)
	}
	return nil
}

// rejectUnfilledAdminVariables refuses an install while a required non-secret
// placeholder is still open on the registry. The admin create form writes
// those values into the server URL; an employee cannot supply them later.
func rejectUnfilledAdminVariables(catalogURL string, declared []registrydomain.MCPURLVariable, bound *registrydomain.MCPTarget) error {
	rowURL := ""
	if bound != nil {
		rowURL = bound.URL
	}
	admin, _ := registrydomain.AdminBoundValues(catalogURL, declared, rowURL)
	for _, variable := range declared {
		if variable.Secret || !variable.Required {
			continue
		}
		if bound.PinsURLVariable(variable.Name) || strings.TrimSpace(admin[variable.Name]) != "" {
			continue
		}
		return fmt.Errorf("%w: variable %q must be set by an admin on the registry", ErrConfigInvalid, variable.Name)
	}
	return nil
}

// installDecision is the outcome of applying the Store access model to one
// install request: which configured instance it binds to (nil = the code's
// canonical instance), whether it installs now or files a request, whether the
// registry must first be materialised from the catalog, or — instead of
// recording anything — that the caller must pick among several instances or
// that an admin must connect the server first.
type installDecision struct {
	registryID ids.RegistryID
	// bound is the instance the install resolved to, even where registryID is
	// left implicit, so the result can be answered from how that instance
	// actually authenticates rather than from the catalog entry alone. Nil when
	// no single instance was resolved (a materialised one, or a pending choice).
	bound *registrydomain.Registry
	// canonical is the code's oldest instance, which serves an install that is
	// not bound to one. Nil while the code has no instance.
	canonical          ids.RegistryID
	status             installationdomain.Status
	materialise        bool
	choices            []InstanceChoice
	requiresAdminSetup bool
}

// refreshBoundCatalog persists a safe catalog correction through Ensure and
// then views that shape on the instance this install already resolved. Custom
// servers are not catalog codes and are skipped.
func (i *installer) refreshBoundCatalog(ctx context.Context, gatewayID ids.GatewayID, code string, decision *installDecision) {
	if i == nil || i.viewer == nil || i.ensurer == nil || decision == nil || decision.bound == nil {
		return
	}
	if _, ok := i.catalog.GetByCode(code); !ok {
		return
	}
	if err := i.ensurer.Ensure(ctx, gatewayID, code); err != nil {
		i.logger.Warn("store: catalog reapply",
			slog.String("code", code),
			slog.String("error", err.Error()),
		)
	}
	if viewed := i.viewer.ViewCurrentCatalog(ctx, decision.bound); viewed != nil {
		decision.bound = viewed
	}
}

// requiresUserAuth reports whether the install still needs the user to sign in
// upstream. An entry that requires auth may be shelved with a static credential
// an admin supplied, and such an instance has no per-user account to connect:
// answered from the catalog entry alone, the caller hands the user a connect
// link that leads to a page with nothing to authorize.
func requiresUserAuth(entry catalogdomain.MCPServer, bound *registrydomain.Registry) bool {
	if bound == nil || bound.MCPTarget == nil || bound.MCPTarget.Auth == nil {
		return entry.RequiresAuth
	}
	return bound.MCPTarget.Auth.Mode == registrydomain.MCPAuthModeForwarded
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
	all, err := findRegistriesByCode(ctx, i.registries, in.GatewayID, code)
	if err != nil {
		return installDecision{}, err
	}
	instances, err := enabledInstances(in, all, code)
	if err != nil {
		return installDecision{}, err
	}
	d, err := i.decideAmong(ctx, in, entry, code, instances)
	if err != nil {
		return installDecision{}, err
	}
	// An implicit binding resolves to the code's oldest registry, a turned-off
	// one included, so with several the instance chosen is pinned.
	if d.registryID.IsNil() && d.bound != nil && len(all) > 1 {
		d.registryID = d.bound.ID
	}
	if len(all) > 0 {
		d.canonical = all[0].ID
	}
	return d, nil
}

// PinTarget is the instance Install would bind in to. Nil when that install
// would not resolve to exactly one instance (the caller must pick, or none
// exists yet): the caller then treats every catalog variable as per-user.
func (i *installer) PinTarget(ctx context.Context, in InstallRequest) (*registrydomain.MCPTarget, error) {
	code := strings.TrimSpace(in.Code)
	entry, ok, err := storeEntry(ctx, i.catalog, i.registries, in.GatewayID, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	decision, err := i.decide(ctx, in, entry, code)
	if err != nil {
		return nil, err
	}
	if len(decision.choices) > 0 {
		return nil, nil
	}
	return boundTarget(decision.bound), nil
}

// enabledInstances narrows a code's instances to the ones an administrator has
// not turned off. Naming a turned-off instance, or a code whose every instance
// is off, is refused rather than decided: materialising a fresh registry for
// it would undo the administrator's decision.
func enabledInstances(in InstallRequest, all []*registrydomain.Registry, code string) ([]*registrydomain.Registry, error) {
	if !in.RegistryID.IsNil() {
		if reg := pickRegistry(all, in.RegistryID); reg != nil && !reg.Enabled {
			return nil, fmt.Errorf("%w: %q", ErrServerDisabled, code)
		}
	}
	out := make([]*registrydomain.Registry, 0, len(all))
	for _, reg := range all {
		if reg != nil && reg.Enabled {
			out = append(out, reg)
		}
	}
	if len(all) > 0 && len(out) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrServerDisabled, code)
	}
	return out, nil
}

func (i *installer) decideAmong(
	ctx context.Context,
	in InstallRequest,
	entry catalogdomain.MCPServer,
	code string,
	instances []*registrydomain.Registry,
) (installDecision, error) {
	grants, err := i.grantSet(ctx, in.GatewayID)
	if err != nil {
		return installDecision{}, err
	}
	grantee := in.grantSubject()
	codeGranted := in.OpenMode || grants.CodeAllows(code, in.Groups, grantee)

	// An explicitly named instance must exist and be an instance of this code.
	if !in.RegistryID.IsNil() {
		reg := pickRegistry(instances, in.RegistryID)
		if reg == nil {
			return installDecision{}, fmt.Errorf("%w: %q is not an instance of %q", ErrUnknownInstance, in.RegistryID, code)
		}
		if codeGranted || grants.Instance(reg.ID).Allows(in.Groups, grantee) {
			return installDecision{registryID: reg.ID, bound: reg, status: installationdomain.StatusInstalled}, nil
		}
		return installDecision{registryID: reg.ID, bound: reg, status: installationdomain.StatusPendingApproval}, nil
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
	// those granted individually. A row whose required admin URL variable is
	// still unfilled is not usable, so it is neither auto-selected nor listed
	// as a choice. The explicit-instance branch above still binds a named
	// unfilled row, and Install refuses it with rejectUnfilledAdminVariables.
	usable := instances
	if !codeGranted {
		usable = usable[:0:0]
		for _, reg := range instances {
			if grants.Instance(reg.ID).Allows(in.Groups, grantee) {
				usable = append(usable, reg)
			}
		}
	}
	if len(usable) > 1 {
		declared := catalogURLVariables(entry.URLVariables)
		filled := make([]*registrydomain.Registry, 0, len(usable))
		for _, reg := range usable {
			if rejectUnfilledAdminVariables(entry.URL, declared, boundTarget(reg)) != nil {
				continue
			}
			filled = append(filled, reg)
		}
		switch {
		case len(filled) > 0:
			usable = filled
		case catalogNeedsAdminCredential(entry):
			return installDecision{requiresAdminSetup: true}, nil
		default:
			if err := rejectUnfilledAdminVariables(entry.URL, declared, boundTarget(usable[0])); err != nil {
				return installDecision{}, err
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
			d.bound = instances[0]
		}
		return d, nil
	case 1:
		// The sole usable instance. When it is also the code's only instance it is
		// the canonical one: leave the binding implicit so the install follows the
		// registry (a re-materialised one included) rather than a stale id.
		d := installDecision{status: installationdomain.StatusInstalled, bound: usable[0]}
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
func (i *installer) Installed(ctx context.Context, in InstallRequest) (*InstallResult, error) {
	code := strings.TrimSpace(in.Code)
	rows, err := i.Instances(ctx, in.GatewayID, in.PrincipalSub, code)
	if err != nil {
		return nil, err
	}
	var held *installationdomain.Installation
	for _, row := range rows {
		// A request is not an install: an approver has not said yes to it yet.
		if row.Status != installationdomain.StatusInstalled {
			continue
		}
		if !in.RegistryID.IsNil() && row.RegistryID != in.RegistryID {
			continue
		}
		if held != nil {
			return nil, ErrNotInstalled
		}
		held = row
	}
	if held == nil {
		return nil, ErrNotInstalled
	}
	entry, ok, err := storeEntry(ctx, i.catalog, i.registries, in.GatewayID, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogEntryNotFound, code)
	}
	instances, err := findRegistriesByCode(ctx, i.registries, in.GatewayID, code)
	if err != nil {
		return nil, err
	}
	// The instance the row is bound to, or the code's canonical one (the
	// oldest), which is what an unbound install is served by.
	bound := pickRegistry(instances, held.RegistryID)
	if held.RegistryID.IsNil() && len(instances) > 0 {
		bound = instances[0]
	}
	return &InstallResult{
		Code:             code,
		Name:             displayName(entry, code),
		Status:           held.Status,
		InstanceID:       held.ID.String(),
		RegistryID:       held.RegistryID,
		RequiresAuth:     requiresUserAuth(entry, bound),
		AlreadyInstalled: true,
	}, nil
}

// InstalledCodes returns the catalog codes this principal has an active
// install of. Pending and revoked rows are not installed.
func (i *installer) InstalledCodes(ctx context.Context, gatewayID ids.GatewayID, principalSub string) (map[string]struct{}, error) {
	rows, err := i.installs.ListByPrincipal(ctx, gatewayID, principalSub)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row == nil || !row.IsActive() {
			continue
		}
		code := strings.TrimSpace(row.CatalogCode)
		if code == "" {
			continue
		}
		out[code] = struct{}{}
	}
	return out, nil
}

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
	var target *installationdomain.Installation
	if id := strings.TrimSpace(instanceID); id != "" {
		installID, err := ids.Parse[ids.InstallationKind](id)
		if err != nil {
			return fmt.Errorf("%w: invalid instance id %q", installationdomain.ErrInvalidInstallation, id)
		}
		found, err := i.installs.FindByID(ctx, gatewayID, principalSub, installID)
		if err != nil {
			return err
		}
		if found.CatalogCode != code {
			return fmt.Errorf("%w: instance %q is not an instance of %q", installationdomain.ErrNotFound, id, code)
		}
		target = found
	} else {
		// Otherwise remove the sole instance; refuse to guess when several exist.
		active, err := i.Instances(ctx, gatewayID, principalSub, code)
		if err != nil {
			return err
		}
		switch len(active) {
		case 0:
			// Nothing active; fall back to clearing any inactive row for the code.
			// A missing row is "nothing was installed", which the caller answers
			// idempotently. Any other delete failure still fails the call.
			err := i.installs.Delete(ctx, gatewayID, principalSub, code)
			if errors.Is(err, installationdomain.ErrNotFound) {
				return ErrNothingInstalled
			}
			return err
		case 1:
			target = active[0]
		default:
			return ErrAmbiguousInstance
		}
	}
	return i.uninstallActive(ctx, gatewayID, principalSub, target)
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
