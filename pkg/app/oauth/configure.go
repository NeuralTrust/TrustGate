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

package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// ErrConfigureInvalid is returned when submitted configuration is malformed (an
// unknown variable, or a value that fails its structure/charset rules).
var ErrConfigureInvalid = errors.New("oauth configure: invalid configuration")

// ErrConfigureIncomplete is returned when a first-time configuration (no
// installation exists yet) omits a required plain value: the install cannot be
// recorded half-configured, so nothing is saved and the form is re-shown.
var ErrConfigureIncomplete = fmt.Errorf("%w: all required values must be provided together", ErrConfigureInvalid)

// ErrConfigureAmbiguous is returned when the ticket names only a catalog code and
// the principal holds several instances of it, so the form cannot tell which one
// to write to. The install tool pins tickets to an instance; this guards tickets
// that were not.
var ErrConfigureAmbiguous = fmt.Errorf("%w: several instances installed; configure from the install result", ErrConfigureInvalid)

// ErrConfigureReasonRequired is returned when a form that must collect the
// requester's words is submitted without them. The request is what an
// administrator decides on, and it is decided on those words.
var ErrConfigureReasonRequired = fmt.Errorf("%w: tell the administrator why you need this server", ErrConfigureInvalid)

// ReasonFormField is the form field the hosted page collects the requester's
// words in. It is prefixed so it cannot be mistaken for a catalog server's own
// URL variable.
const ReasonFormField = "__reason"

// ErrConfigureInstallUnavailable is returned when a configure-before-install
// would need to record the installation but no installer is wired, so the
// governed install path cannot run. The user installs first, then configures.
var ErrConfigureInstallUnavailable = fmt.Errorf("%w: install the server first, then configure it", ErrConfigureInvalid)

// ConfigureVariable is one per-user URL variable shown on the hosted form.
type ConfigureVariable struct {
	Name        string
	Description string
	Required    bool
	Secret      bool
	// Set reports whether a value is already stored for this principal (plain in
	// the installation config, secret in the vault), so the form can show it as
	// already provided without ever echoing the value.
	Set bool
}

// ConfigurePage is the state the hosted "configure" form renders.
type ConfigurePage struct {
	ConsumerPath string
	Code         string
	ServerName   string
	Variables    []ConfigureVariable
	// Saved is true after a successful submit, so the page can confirm.
	Saved bool
	// Pending is true when the submit recorded the install as a request awaiting
	// admin approval (the server is governed), so the page can say so rather than
	// implying the tools are live.
	Pending bool
	// AskReason is true when this form is where the requester says why they need
	// the server: the install is outside their access, so submitting files a
	// request an administrator decides on, and these are the words they read.
	AskReason bool
}

// ConfigureTicketRequest scopes a configure ticket: the (gateway, principal,
// consumer, catalog code) the hosted form writes for, optionally pinned to one
// installation instance, plus the principal's groups so a form-driven install is
// governed exactly like a tool-driven one.
type ConfigureTicketRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	ConsumerPath string
	Code         string
	// InstanceID pins the ticket to one installation instance of Code. Empty when
	// the install recorded no row yet (requires-config before install).
	InstanceID string
	// Groups are the principal's IdP groups at mint time (from their token).
	Groups []string
	// Reason is the requester's words from the install that needs this form, kept
	// so the install the submit files can be a request (see ConnectTicket.Reason).
	Reason string
	// AskReason makes this form collect those words itself, for an install that
	// was refused for want of them. The requester writes them here because they
	// are the only acceptable author (see ConnectTicket.AskReason).
	AskReason bool
}

// ConfigureInstaller is the governed install path the configure flow records a
// first-time configuration through. appstore.Installer satisfies it.
type ConfigureInstaller interface {
	Install(ctx context.Context, in appstore.InstallRequest) (*appstore.InstallResult, error)
}

//go:generate mockery --name=ConfigureService --dir=. --output=./mocks --filename=oauth_configure_service_mock.go --case=underscore --with-expecter
type ConfigureService interface {
	// CreateTicket mints a short-lived ticket scoping the hosted form to one
	// (gateway, principal, consumer, catalog code[, instance]).
	CreateTicket(ctx context.Context, in ConfigureTicketRequest) (string, error)
	// Page returns the variables to render for a ticket and whether each is set.
	Page(ctx context.Context, ticketID string) (*ConfigurePage, error)
	// Submit validates and stores the submitted values (plain to the installation
	// config, secret to the vault) and returns the refreshed page.
	Submit(ctx context.Context, ticketID string, values map[string]string) (*ConfigurePage, error)
}

var _ ConfigureService = (*configureService)(nil)

type configureService struct {
	store     ConnectStore
	consumers appconsumer.DataFinder
	catalog   authCatalog
	installs  installationdomain.Repository
	vault     vaultdomain.Repository
	installer ConfigureInstaller
	// openMode reports whether the gateway's Store is open (self-service) for a
	// form-driven first install. Nil means "not open": the install is governed as
	// a request unless the shelf says otherwise.
	openMode func(ctx context.Context, gatewayID ids.GatewayID) bool
}

// ConfigureOption tunes the configure service.
type ConfigureOption func(*configureService)

// WithConfigureInstaller wires the governed installer a configure-before-install
// submission is recorded through. Without it, configuring a server that has no
// installation yet is refused (ErrConfigureInstallUnavailable) — the form never
// creates an installation row on its own.
func WithConfigureInstaller(installer ConfigureInstaller) ConfigureOption {
	return func(s *configureService) { s.installer = installer }
}

// WithConfigureOpenMode supplies how the service decides whether the gateway's
// Store is open (self-service) when it must record a first install from the
// form. Without it, form-driven installs are always treated as curated.
func WithConfigureOpenMode(fn func(ctx context.Context, gatewayID ids.GatewayID) bool) ConfigureOption {
	return func(s *configureService) { s.openMode = fn }
}

// NewConfigureService wires the MCP-Store per-user configuration flow: it collects
// the URL variables a catalog server declares (e.g. a Snowflake account URL, a
// Bright Data token) from the user through a hosted form, storing plain values on
// their installation and secret values in the vault — the same places the dial
// path reads them from. The form never creates an installation itself: a
// configure-before-install submission is routed through the governed installer
// so shelf availability, approval and group gates apply exactly as they do to the
// install tool.
func NewConfigureService(
	store ConnectStore,
	consumers appconsumer.DataFinder,
	catalog authCatalog,
	installs installationdomain.Repository,
	vault vaultdomain.Repository,
	opts ...ConfigureOption,
) ConfigureService {
	s := &configureService{store: store, consumers: consumers, catalog: catalog, installs: installs, vault: vault}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

func (s *configureService) CreateTicket(ctx context.Context, in ConfigureTicketRequest) (string, error) {
	code := strings.TrimSpace(in.Code)
	if code == "" {
		return "", fmt.Errorf("%w: code is required", ErrConfigureInvalid)
	}
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := s.store.SaveTicket(ctx, id, ConnectTicket{
		GatewayID:    in.GatewayID.String(),
		PrincipalSub: in.PrincipalSub,
		ConsumerPath: in.ConsumerPath,
		Code:         code,
		InstanceID:   strings.TrimSpace(in.InstanceID),
		Groups:       append([]string(nil), in.Groups...),
		Reason:       strings.TrimSpace(in.Reason),
		AskReason:    in.AskReason,
	}); err != nil {
		return "", err
	}
	return id, nil
}

func (s *configureService) Page(ctx context.Context, ticketID string) (*ConfigurePage, error) {
	ticket, gatewayID, entry, err := s.resolve(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	return s.page(ctx, gatewayID, ticket, entry, false, false)
}

func (s *configureService) Submit(
	ctx context.Context,
	ticketID string,
	values map[string]string,
) (*ConfigurePage, error) {
	ticket, gatewayID, entry, err := s.resolve(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	// The requester's own words, when this form is the one that asks for them.
	// Taken before the variables are read so the reserved field is never
	// mistaken for one the catalog declared.
	if reason := trimReason(values[ReasonFormField]); ticket.AskReason {
		if reason == "" {
			return nil, ErrConfigureReasonRequired
		}
		ticket.Reason = reason
	}
	byName := make(map[string]catalogdomain.MCPURLVariable, len(entry.URLVariables))
	for _, v := range entry.URLVariables {
		byName[strings.TrimSpace(v.Name)] = v
	}
	plain := map[string]string{}
	secrets := map[string]string{}
	for k, raw := range values {
		if k == ReasonFormField {
			continue
		}
		val := strings.TrimSpace(raw)
		if val == "" {
			continue
		}
		v, ok := byName[k]
		if !ok {
			return nil, fmt.Errorf("%w: unknown variable %q", ErrConfigureInvalid, k)
		}
		if err := registrydomain.ValidateURLValue(toRegistryURLVar(v), val); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfigureInvalid, err)
		}
		if v.Secret {
			secrets[k] = val
			continue
		}
		plain[k] = val
	}
	// Plain values first: a first-time configuration is a governed install, and
	// nothing (not even the secrets) is stored if it is refused.
	pending := false
	if len(plain) > 0 || ticket.AskReason {
		// A reason-only form has nothing to store: submitting it is what files the
		// request, so the governed install still has to run.
		pending, err = s.storePlain(ctx, gatewayID, ticket, plain)
		if err != nil {
			return nil, err
		}
	}
	for k, val := range secrets {
		if err := s.storeSecret(ctx, gatewayID, ticket.PrincipalSub, ticket.Code, k, val); err != nil {
			return nil, err
		}
	}
	return s.page(ctx, gatewayID, ticket, entry, true, pending)
}

// resolve loads a configure ticket and its catalog entry, rejecting a ticket that
// is missing, expired, not a configure ticket, or whose consumer/code no longer
// exists.
func (s *configureService) resolve(
	ctx context.Context,
	ticketID string,
) (*ConnectTicket, ids.GatewayID, catalogdomain.MCPServer, error) {
	ticket, err := s.store.GetTicket(ctx, ticketID)
	if err != nil {
		return nil, ids.GatewayID{}, catalogdomain.MCPServer{}, err
	}
	if ticket == nil || strings.TrimSpace(ticket.Code) == "" {
		return nil, ids.GatewayID{}, catalogdomain.MCPServer{}, ErrTicketNotFound
	}
	gatewayID, _, _, err := baseRoutable(ctx, s.consumers, ticket)
	if err != nil {
		return nil, ids.GatewayID{}, catalogdomain.MCPServer{}, err
	}
	entry, ok := s.catalog.GetByCode(ticket.Code)
	if !ok {
		return nil, ids.GatewayID{}, catalogdomain.MCPServer{}, ErrTicketNotFound
	}
	return ticket, gatewayID, entry, nil
}

func (s *configureService) page(
	ctx context.Context,
	gatewayID ids.GatewayID,
	ticket *ConnectTicket,
	entry catalogdomain.MCPServer,
	saved, pending bool,
) (*ConfigurePage, error) {
	inst, _ := s.instance(ctx, gatewayID, ticket)
	var config map[string]string
	if inst != nil {
		config = inst.Config
		pending = pending || inst.Status == installationdomain.StatusPendingApproval
	}
	vars := make([]ConfigureVariable, 0, len(entry.URLVariables))
	for _, v := range entry.URLVariables {
		name := strings.TrimSpace(v.Name)
		vars = append(vars, ConfigureVariable{
			Name:        name,
			Description: v.Description,
			Required:    v.Required,
			Secret:      v.Secret,
			Set:         s.isSet(ctx, gatewayID, ticket.PrincipalSub, ticket.Code, v, config),
		})
	}
	return &ConfigurePage{
		ConsumerPath: ticket.ConsumerPath,
		Code:         ticket.Code,
		ServerName:   serverName(entry),
		Variables:    vars,
		Saved:        saved,
		Pending:      pending,
		// Answered once, the field is done: the page that follows a submit
		// reports what happened instead of asking again.
		AskReason: ticket.AskReason && !saved,
	}, nil
}

func (s *configureService) isSet(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code string,
	v catalogdomain.MCPURLVariable,
	config map[string]string,
) bool {
	if v.Secret {
		if s.vault == nil {
			return false
		}
		_, err := s.vault.Find(ctx, gatewayID, principalSub, registrydomain.URLVariableVaultProvider(code, v.Name))
		return err == nil
	}
	return strings.TrimSpace(config[strings.TrimSpace(v.Name)]) != ""
}

// instance resolves the installation the ticket targets. A ticket pinned to an
// instance id reads exactly that row (which must belong to the principal and the
// ticket's code). An unpinned ticket falls back to the code, which is only
// unambiguous when the principal holds at most one live instance of it; with
// several, ErrConfigureAmbiguous. (nil, nil) when no installation exists yet.
func (s *configureService) instance(
	ctx context.Context,
	gatewayID ids.GatewayID,
	ticket *ConnectTicket,
) (*installationdomain.Installation, error) {
	if id := strings.TrimSpace(ticket.InstanceID); id != "" {
		installID, err := ids.Parse[ids.InstallationKind](id)
		if err != nil {
			return nil, ErrTicketNotFound
		}
		inst, err := s.installs.FindByID(ctx, gatewayID, ticket.PrincipalSub, installID)
		if err != nil {
			if errors.Is(err, installationdomain.ErrNotFound) {
				return nil, ErrTicketNotFound
			}
			return nil, err
		}
		if inst.CatalogCode != ticket.Code {
			return nil, ErrTicketNotFound
		}
		return inst, nil
	}
	rows, err := s.installs.ListByPrincipalAndCode(ctx, gatewayID, ticket.PrincipalSub, ticket.Code)
	if err != nil {
		return nil, err
	}
	var live []*installationdomain.Installation
	for _, r := range rows {
		if r != nil && r.Status != installationdomain.StatusRevoked {
			live = append(live, r)
		}
	}
	switch len(live) {
	case 0:
		return nil, nil
	case 1:
		return live[0], nil
	default:
		return nil, ErrConfigureAmbiguous
	}
}

func (s *configureService) storeSecret(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code, name, value string,
) error {
	cred, err := vaultdomain.NewCredential(
		gatewayID, principalSub,
		registrydomain.URLVariableVaultProvider(code, name),
		"", value, "", nil, time.Time{},
	)
	if err != nil {
		return err
	}
	return s.vault.Upsert(ctx, cred)
}

// storePlain applies plain values to the principal's installation. When the
// ticket targets an existing instance the values are merged into that instance
// in place (its status — installed or pending — is untouched). When no
// installation exists yet, the form never creates one itself: the values are
// handed to the governed installer, so the shelf/approval/group decision that
// applies to the install tool applies here too, and the result may be a pending
// request rather than an install. Returns whether the install is pending.
func (s *configureService) storePlain(
	ctx context.Context,
	gatewayID ids.GatewayID,
	ticket *ConnectTicket,
	plain map[string]string,
) (bool, error) {
	inst, err := s.instance(ctx, gatewayID, ticket)
	if err != nil {
		return false, err
	}
	if inst == nil {
		return s.installConfigured(ctx, gatewayID, ticket, plain)
	}
	merged := make(map[string]string, len(inst.Config)+len(plain))
	for k, v := range inst.Config {
		merged[k] = v
	}
	for k, v := range plain {
		merged[k] = v
	}
	inst.Config = merged
	inst.UpdatedAt = time.Now().UTC()
	if err := s.installs.Upsert(ctx, inst); err != nil {
		return false, err
	}
	return inst.Status == installationdomain.StatusPendingApproval, nil
}

// installConfigured records a first-time configuration through the governed
// installer. A refusal (role, caps) surfaces as-is; a requires-config result
// means a required plain value was omitted and nothing was recorded.
func (s *configureService) installConfigured(
	ctx context.Context,
	gatewayID ids.GatewayID,
	ticket *ConnectTicket,
	plain map[string]string,
) (bool, error) {
	if s.installer == nil {
		return false, ErrConfigureInstallUnavailable
	}
	open := false
	if s.openMode != nil {
		open = s.openMode(ctx, gatewayID)
	}
	res, err := s.installer.Install(ctx, appstore.InstallRequest{
		GatewayID:    gatewayID,
		PrincipalSub: ticket.PrincipalSub,
		Code:         ticket.Code,
		InstalledBy:  ticket.PrincipalSub,
		Groups:       ticket.Groups,
		OpenMode:     open,
		Config:       plain,
		Reason:       ticket.Reason,
	})
	if err != nil {
		if errors.Is(err, appstore.ErrConfigInvalid) {
			return false, fmt.Errorf("%w: %w", ErrConfigureInvalid, err)
		}
		return false, err
	}
	if res.RequiresConfig && res.InstanceID == "" {
		names := make([]string, 0, len(res.ConfigVariables))
		for _, v := range res.ConfigVariables {
			names = append(names, v.Name)
		}
		return false, fmt.Errorf("%w: missing %s", ErrConfigureIncomplete, strings.Join(names, ", "))
	}
	if res.RequiresAdminSetup {
		return false, fmt.Errorf("%w: an admin must connect this server first", ErrConfigureInvalid)
	}
	// Pin the ticket to the instance just recorded so later submits on the same
	// form target it even if another instance of the code appears meanwhile.
	ticket.InstanceID = res.InstanceID
	return res.Pending, nil
}

// trimReason bounds what the form may submit as the requester's words to what
// the domain keeps, so a long answer is shortened rather than refused.
func trimReason(reason string) string {
	reason = strings.TrimSpace(reason)
	runes := []rune(reason)
	if len(runes) <= installationdomain.MaxReasonLength {
		return reason
	}
	return strings.TrimSpace(string(runes[:installationdomain.MaxReasonLength]))
}

func toRegistryURLVar(v catalogdomain.MCPURLVariable) registrydomain.MCPURLVariable {
	return registrydomain.MCPURLVariable{
		Name:        strings.TrimSpace(v.Name),
		Description: v.Description,
		Required:    v.Required,
		Secret:      v.Secret,
		In:          strings.TrimSpace(v.In),
	}
}

func serverName(entry catalogdomain.MCPServer) string {
	if n := strings.TrimSpace(entry.DisplayName); n != "" {
		return n
	}
	if n := strings.TrimSpace(entry.Vendor); n != "" {
		return n
	}
	return entry.Code
}

// StoreConfigureTickets adapts the configure service to the port the Store's
// principal-configure linker needs (appstore.ConfigureTicketMinter). It lives
// here because app/oauth already imports app/store; the reverse would be a
// cycle, so the store side names only the method it calls.
type StoreConfigureTickets struct {
	Service ConfigureService
}

func (t StoreConfigureTickets) CreateConfigureTicket(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, consumerPath, code, instanceID string,
	groups []string,
) (string, error) {
	if t.Service == nil {
		return "", ErrConfigureInvalid
	}
	return t.Service.CreateTicket(ctx, ConfigureTicketRequest{
		GatewayID:    gatewayID,
		PrincipalSub: principalSub,
		ConsumerPath: consumerPath,
		Code:         code,
		InstanceID:   instanceID,
		Groups:       groups,
	})
}
