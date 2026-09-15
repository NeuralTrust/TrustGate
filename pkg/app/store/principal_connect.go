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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ServerTicketMinter mints a connect ticket scoped to one catalog server for one
// principal. appoauth.ConnectService satisfies it.
type ServerTicketMinter interface {
	CreateServerTicket(
		ctx context.Context,
		gatewayID ids.GatewayID,
		principalSub, consumerPath, code, instanceID string,
	) (string, error)
}

// PrincipalConnectRequest asks for the connect link one principal opens to sign
// in to one Store server with their own account.
type PrincipalConnectRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	RegistryID   ids.RegistryID
}

// PrincipalConnectLink is the minted ticket and where it is redeemed. The URL is
// composed by the caller: only the gateway's MCP host serves the connect page
// and the admin API answers on another one, so the host is the console's to
// know (same split as a consumer's upstream-accounts link). The lifetime is the
// connect flow's own (appoauth.ConnectTicketTTL) and is stamped by the handler,
// which can name it without this package depending on that one.
type PrincipalConnectLink struct {
	Ticket       string
	ConsumerPath string
}

// PrincipalConnectLinker hands a Store user the link to sign in to a server they
// hold, so the Portal can offer it instead of reporting "not connected" and
// leaving them to trigger a tool call from an MCP client to be handed one.
//
//go:generate mockery --name=PrincipalConnectLinker --dir=. --output=./mocks --filename=store_principal_connect_linker_mock.go --case=underscore --with-expecter
type PrincipalConnectLinker interface {
	LinkFor(ctx context.Context, in PrincipalConnectRequest) (*PrincipalConnectLink, error)
}

type principalConnectLinker struct {
	tickets ServerTicketMinter
}

func NewPrincipalConnectLinker(tickets ServerTicketMinter) (PrincipalConnectLinker, error) {
	if tickets == nil {
		return nil, ErrUnavailable
	}
	return &principalConnectLinker{tickets: tickets}, nil
}

// LinkFor mints the ticket against the Store's own consumer path: the Store is
// the surface these installs live on, so the page it opens is the same one a
// tool call would have handed the user, focused on the server they asked about.
func (l *principalConnectLinker) LinkFor(
	ctx context.Context,
	in PrincipalConnectRequest,
) (*PrincipalConnectLink, error) {
	if in.GatewayID.IsNil() {
		return nil, fmt.Errorf("store: gateway id is required: %w", commonerrors.ErrValidation)
	}
	principalSub := strings.TrimSpace(in.PrincipalSub)
	code := strings.TrimSpace(in.Code)
	if principalSub == "" || code == "" {
		return nil, fmt.Errorf("store: principal and code are required: %w", commonerrors.ErrValidation)
	}
	consumerPath := appconsumer.MCPPath(consumerdomain.StoreSlug)
	instanceID := ""
	if !in.RegistryID.IsNil() {
		instanceID = in.RegistryID.String()
	}
	ticket, err := l.tickets.CreateServerTicket(ctx, in.GatewayID, principalSub, consumerPath, code, instanceID)
	if err != nil {
		return nil, err
	}
	return &PrincipalConnectLink{Ticket: ticket, ConsumerPath: consumerPath}, nil
}
