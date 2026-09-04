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
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// ErrConfigureInvalid is returned when submitted configuration is malformed (an
// unknown variable, or a value that fails its structure/charset rules).
var ErrConfigureInvalid = errors.New("oauth configure: invalid configuration")

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
}

//go:generate mockery --name=ConfigureService --dir=. --output=./mocks --filename=oauth_configure_service_mock.go --case=underscore --with-expecter
type ConfigureService interface {
	// CreateTicket mints a short-lived ticket scoping the hosted form to one
	// (gateway, principal, consumer, catalog code).
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath, code string) (string, error)
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
}

// NewConfigureService wires the MCP-Store per-user configuration flow: it collects
// the URL variables a catalog server declares (e.g. a Snowflake account URL, a
// Bright Data token) from the user through a hosted form, storing plain values on
// their installation and secret values in the vault — the same places the dial
// path reads them from.
func NewConfigureService(
	store ConnectStore,
	consumers appconsumer.DataFinder,
	catalog authCatalog,
	installs installationdomain.Repository,
	vault vaultdomain.Repository,
) ConfigureService {
	return &configureService{store: store, consumers: consumers, catalog: catalog, installs: installs, vault: vault}
}

func (s *configureService) CreateTicket(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, consumerPath, code string,
) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", fmt.Errorf("%w: code is required", ErrConfigureInvalid)
	}
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := s.store.SaveTicket(ctx, id, ConnectTicket{
		GatewayID:    gatewayID.String(),
		PrincipalSub: principalSub,
		ConsumerPath: consumerPath,
		Code:         code,
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
	return s.page(ctx, gatewayID, ticket, entry, false)
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
	byName := make(map[string]catalogdomain.MCPURLVariable, len(entry.URLVariables))
	for _, v := range entry.URLVariables {
		byName[strings.TrimSpace(v.Name)] = v
	}
	plain := map[string]string{}
	for k, raw := range values {
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
			if err := s.storeSecret(ctx, gatewayID, ticket.PrincipalSub, ticket.Code, k, val); err != nil {
				return nil, err
			}
			continue
		}
		plain[k] = val
	}
	if len(plain) > 0 {
		if err := s.storePlain(ctx, gatewayID, ticket.PrincipalSub, ticket.Code, plain); err != nil {
			return nil, err
		}
	}
	return s.page(ctx, gatewayID, ticket, entry, true)
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
	saved bool,
) (*ConfigurePage, error) {
	config := s.installConfig(ctx, gatewayID, ticket.PrincipalSub, ticket.Code)
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

func (s *configureService) installConfig(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code string,
) map[string]string {
	inst, err := s.installs.Find(ctx, gatewayID, principalSub, code)
	if err != nil || inst == nil {
		return nil
	}
	return inst.Config
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

// storePlain merges plain values into the principal's installation config,
// creating the installation when the user configures before installing.
func (s *configureService) storePlain(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code string,
	plain map[string]string,
) error {
	inst, err := s.installs.Find(ctx, gatewayID, principalSub, code)
	if err != nil {
		if !errors.Is(err, installationdomain.ErrNotFound) {
			return err
		}
		created, cerr := installationdomain.New(gatewayID, principalSub, code, principalSub, plain)
		if cerr != nil {
			return cerr
		}
		return s.installs.Upsert(ctx, created)
	}
	merged := make(map[string]string, len(inst.Config)+len(plain))
	for k, v := range inst.Config {
		merged[k] = v
	}
	for k, v := range plain {
		merged[k] = v
	}
	inst.Config = merged
	return s.installs.Upsert(ctx, inst)
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
