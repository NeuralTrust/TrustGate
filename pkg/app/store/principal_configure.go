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
	"fmt"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// ConfigureTicketMinter mints a ticket for the hosted form where a user enters
// a server's per-user values. appoauth.ConfigureService satisfies it through a
// small adapter, which is why the request is spelled out here rather than
// importing that package (app/oauth imports app/store, not the other way).
type ConfigureTicketMinter interface {
	CreateConfigureTicket(
		ctx context.Context,
		gatewayID ids.GatewayID,
		principalSub, consumerPath, code, instanceID string,
		groups []string,
	) (string, error)
}

// PrincipalConfigureRequest asks for the form one principal fills in to finish
// setting up one server they hold.
type PrincipalConfigureRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	// InstanceID pins the form to one installation instance, so it writes to
	// that row rather than to whichever one carries the code.
	InstanceID string
	// Groups are the principal's groups, carried on the ticket so a form-driven
	// install is governed exactly as a tool-driven one.
	Groups []string
}

// PrincipalConfigureLink is the minted ticket and where it is redeemed. As with
// the connect link, the URL is composed by the caller: only the gateway's MCP
// host serves the form, and the admin API answers on another one.
type PrincipalConfigureLink struct {
	Ticket       string
	ConsumerPath string
}

// PrincipalConfigureLinker hands a Store user the form that collects a server's
// per-user values, so the Portal can offer it instead of telling them to go and
// re-run the install from an MCP client — which was the only place the gateway
// ever handed the link out.
//
//go:generate mockery --name=PrincipalConfigureLinker --dir=. --output=./mocks --filename=store_principal_configure_linker_mock.go --case=underscore --with-expecter
type PrincipalConfigureLinker interface {
	LinkFor(ctx context.Context, in PrincipalConfigureRequest) (*PrincipalConfigureLink, error)
}

type principalConfigureLinker struct {
	tickets    ConfigureTicketMinter
	registries RegistryLister
	grants     storeaccessdomain.Reader
	modes      ModeResolver
	gateways   GatewayFinder
}

func NewPrincipalConfigureLinker(
	tickets ConfigureTicketMinter,
	registries RegistryLister,
	grants storeaccessdomain.Reader,
	modes ModeResolver,
	gateways GatewayFinder,
) (PrincipalConfigureLinker, error) {
	if tickets == nil || registries == nil {
		return nil, ErrUnavailable
	}
	return &principalConfigureLinker{
		tickets: tickets, registries: registries, grants: grants, modes: modes, gateways: gateways,
	}, nil
}

func (l *principalConfigureLinker) LinkFor(
	ctx context.Context,
	in PrincipalConfigureRequest,
) (*PrincipalConfigureLink, error) {
	if in.GatewayID.IsNil() {
		return nil, fmt.Errorf("store: gateway id is required: %w", commonerrors.ErrValidation)
	}
	principalSub := strings.TrimSpace(in.PrincipalSub)
	code := strings.TrimSpace(in.Code)
	if principalSub == "" || code == "" {
		return nil, fmt.Errorf("store: principal and code are required: %w", commonerrors.ErrValidation)
	}
	groups := identity.GroupsFromClaim(in.Groups)
	fallback := gatewaydomain.StoreModeCurated
	if l.gateways != nil {
		gateway, err := l.gateways.FindByID(ctx, in.GatewayID)
		if err != nil {
			return nil, fmt.Errorf("store: load gateway: %w", err)
		}
		if gateway != nil {
			fallback = gateway.StoreMode()
		}
	}
	mode := ResolveMode(ctx, l.modes, ModeQuery{
		GatewayID: in.GatewayID,
		Subject:   principalSub,
		Groups:    groups,
		Fallback:  fallback,
	})
	if mode == gatewaydomain.StoreModeNone {
		return nil, ErrStoreClosed
	}
	registries, err := findRegistriesByCode(ctx, l.registries, in.GatewayID, code)
	if err != nil {
		return nil, err
	}
	var grants *storeaccessdomain.Set
	if mode != gatewaydomain.StoreModeOpen {
		grants, err = loadGrantSet(ctx, l.grants, in.GatewayID)
		if err != nil {
			return nil, err
		}
	}
	allowed := false
	for _, registry := range registries {
		if registry != nil && registry.Enabled &&
			(mode == gatewaydomain.StoreModeOpen || grants.InstanceAllows(code, registry.ID, groups, principalSub)) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("store: no enabled instance is granted to this principal: %w", commonerrors.ErrForbidden)
	}
	consumerPath := appconsumer.MCPPath(consumerdomain.StoreSlug)
	ticket, err := l.tickets.CreateConfigureTicket(
		ctx, in.GatewayID, principalSub, consumerPath, code, strings.TrimSpace(in.InstanceID), groups,
	)
	if err != nil {
		return nil, err
	}
	return &PrincipalConfigureLink{Ticket: ticket, ConsumerPath: consumerPath}, nil
}
