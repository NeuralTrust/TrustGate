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

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ErrStoreClosed: the principal's live access level is None, so nothing can be
// installed or requested for them (the Portal shows "Unavailable").
var ErrStoreClosed = fmt.Errorf("store: access level is None for this principal: %w", commonerrors.ErrConflict)

// OnBehalfInstallRequest is an install (or request) an admin makes for a user
// from the Portal: the same decision the user's own client would get.
type OnBehalfInstallRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	// Groups are the keys the principal's group memberships match on (the app
	// resolves them from its directory, as the token mint does).
	Groups []string
	// RegistryID picks one configured instance after a RequiresInstanceChoice.
	RegistryID ids.RegistryID
	// Actor is the admin acting, for audit (installed_by).
	Actor string
	// Reason is why the user wants the server, in their own words, kept on a
	// request for the approver to read.
	Reason string
}

// PrincipalInstaller runs the Store installer as another principal, resolving
// their live access level first (own policy → groups → gateway default) exactly
// as the install tool does, so the Portal's Request access / Install buttons
// produce what the user would have produced.
//
//go:generate mockery --name=PrincipalInstaller --dir=. --output=./mocks --filename=store_principal_installer_mock.go --case=underscore --with-expecter
type PrincipalInstaller interface {
	InstallFor(ctx context.Context, in OnBehalfInstallRequest) (*InstallResult, error)
}

// GatewayFinder loads the gateway whose default Store mode applies when no policy
// names the principal.
type GatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

type principalInstaller struct {
	installer Installer
	modes     ModeResolver
	gateways  GatewayFinder
}

// NewPrincipalInstaller wires the on-behalf installer. modes may be nil (then
// only the gateway default applies); gateways may be nil (then an unknown
// default fails closed to curated).
func NewPrincipalInstaller(installer Installer, modes ModeResolver, gateways GatewayFinder) (PrincipalInstaller, error) {
	if installer == nil {
		return nil, ErrUnavailable
	}
	return &principalInstaller{installer: installer, modes: modes, gateways: gateways}, nil
}

func (p *principalInstaller) InstallFor(ctx context.Context, in OnBehalfInstallRequest) (*InstallResult, error) {
	sub := strings.TrimSpace(in.PrincipalSub)
	code := strings.TrimSpace(in.Code)
	if in.GatewayID.IsNil() {
		return nil, fmt.Errorf("gateway id is required: %w", commonerrors.ErrValidation)
	}
	if sub == "" {
		return nil, fmt.Errorf("principal subject is required: %w", commonerrors.ErrValidation)
	}
	if code == "" {
		return nil, fmt.Errorf("code is required: %w", commonerrors.ErrValidation)
	}
	groups := identity.GroupsFromClaim(in.Groups)
	fallback := gatewaydomain.StoreModeCurated
	if p.gateways != nil {
		gw, err := p.gateways.FindByID(ctx, in.GatewayID)
		if err != nil {
			return nil, fmt.Errorf("store: load gateway: %w", err)
		}
		if gw != nil {
			fallback = gw.StoreMode()
		}
	}
	mode := ResolveMode(ctx, p.modes, ModeQuery{
		GatewayID: in.GatewayID,
		Subject:   sub,
		Groups:    groups,
		Fallback:  fallback,
	})
	if mode == gatewaydomain.StoreModeNone {
		return nil, ErrStoreClosed
	}
	actor := strings.TrimSpace(in.Actor)
	if actor == "" {
		actor = sub
	}
	return p.installer.Install(ctx, InstallRequest{
		GatewayID:    in.GatewayID,
		PrincipalSub: sub,
		Code:         code,
		InstalledBy:  actor,
		Groups:       groups,
		OpenMode:     mode == gatewaydomain.StoreModeOpen,
		RegistryID:   in.RegistryID,
		Reason:       in.Reason,
	})
}
