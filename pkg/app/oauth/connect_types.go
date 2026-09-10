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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

var (
	ErrTicketNotFound     = errors.New("oauth connect: ticket expired or unknown")
	ErrProviderNotFound   = errors.New("oauth connect: provider not configured for this consumer")
	ErrNoRegisteredClient = errors.New("oauth connect: no dynamically registered client for this upstream")
)

type ConnectTicket struct {
	GatewayID    string    `json:"gateway_id"`
	PrincipalSub string    `json:"principal_sub"`
	ConsumerPath string    `json:"consumer_path"`
	ResumeURL    string    `json:"resume_url,omitempty"`
	ConsumerID   string    `json:"consumer_id,omitempty"`
	AuthID       string    `json:"auth_id,omitempty"`
	Providers    *[]string `json:"providers,omitempty"`
	// Code scopes a configure ticket to one catalog server whose per-user URL
	// variables the hosted form collects. Empty for OAuth/api-key connect tickets.
	Code string `json:"code,omitempty"`
	// InstanceID pins a Store-scoped ticket (configure or single-server connect)
	// to one exact installation instance of Code, so the form writes to that
	// instance rather than to "whichever row has this code" when the principal
	// holds several. Empty when the install recorded no row yet.
	InstanceID string `json:"instance_id,omitempty"`
	// Groups snapshots the principal's IdP groups at mint time so a form-driven
	// install (configure before install) applies the same group gate the install
	// tool applied — the browser submitting the form carries no token.
	Groups []string `json:"groups,omitempty"`
}

type ConnectState struct {
	Ticket   ConnectTicket `json:"ticket"`
	TicketID string        `json:"ticket_id"`
	Provider string        `json:"provider"`
	// Instance is the registry the authorization was started for, so the
	// callback stores the credential for that instance instead of re-deriving it
	// from the provider — which cannot tell two instances of one provider apart.
	Instance string `json:"instance,omitempty"`
	Verifier string `json:"verifier,omitempty"`
}

type ConnectStore interface {
	SaveTicket(ctx context.Context, id string, t ConnectTicket) error
	GetTicket(ctx context.Context, id string) (*ConnectTicket, error)
	SaveConnect(ctx context.Context, state string, s ConnectState) error
	TakeConnect(ctx context.Context, state string) (*ConnectState, error)
}

type ProviderStatus struct {
	Provider string
	Registry string
	// Instance is the registry id this row is for. Two instances of one catalog
	// code appear as two rows with the same Provider, and it is what a connect
	// or revoke action names to act on this one.
	Instance   string
	Code       string
	Linked     bool
	AccountRef string
	// Scopes are the scopes the upstream actually granted, as recorded on the
	// stored credential. Empty when nothing is linked, or when the provider's
	// token response omitted "scope" — it is never the catalog's declaration.
	Scopes         []string
	ExpiresAt      time.Time
	NeedsReconnect bool
}

type ConnectPage struct {
	ConsumerPath string
	Providers    []ProviderStatus
	ResumeURL    string
	// Code, when set, scopes the page to a single catalog server (the ticket was
	// minted for one server, e.g. from a Store install) so the connect page shows
	// just that server rather than every provider.
	Code string
	// Instance, when set, is the exact registry the ticket was minted for, so a
	// single-server page of a code with several instances shows that one instead
	// of whichever came first.
	Instance string
}

//go:generate mockery --name=ConnectService --dir=. --output=./mocks --filename=oauth_connect_service_mock.go --case=underscore --with-expecter
type ConnectService interface {
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error)
	// CreateServerTicket mints a connect ticket scoped to one catalog server, so
	// the connect page opens focused on that server (e.g. from a Store install).
	// instanceID optionally pins the ticket to the exact installation instance
	// the install recorded; empty when none was.
	CreateServerTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath, code, instanceID string) (string, error)
	// CreateAppTicket mints a connect ticket for an application's own upstream
	// accounts, pinned to that consumer and to the providers bound to it at mint
	// time. authID is the api key the ticket was minted from, so revoking that
	// key kills it; pass a nil id for a ticket an admin minted, whose authority
	// was the admin API and which stands on the consumer alone.
	//
	// code is the catalog code of the one server the ticket is focused on, which
	// opens the connect page on that server's own card instead of the picker —
	// what an admin authorizing a single row asked for. Empty covers every
	// forwarded server of the application, and the picker is then the point.
	CreateAppTicket(
		ctx context.Context,
		gatewayID ids.GatewayID,
		principalSub,
		consumerPath string,
		consumerID ids.ConsumerID,
		authID ids.AuthID,
		providers []string,
		code string,
	) (string, error)
	Page(ctx context.Context, ticketID string) (*ConnectPage, error)
	Statuses(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) ([]ProviderStatus, error)
	Start(ctx context.Context, baseURL, ticketID, provider, instanceID string) (string, error)
	Callback(ctx context.Context, baseURL, provider, state, code, errCode, errDesc string) (string, error)
	Disconnect(ctx context.Context, ticketID, provider, instanceID string) error
	RefreshAuth(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error)
	// CredentialUsable reports whether a credential stored for this registry can
	// still be redeemed: for a dynamically registered client, that registration
	// has to still exist. It is what keeps a reader of the vault from calling an
	// account connected while every tool call on it asks the user to connect.
	CredentialUsable(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (bool, error)
	ChainURL(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, principalSub, resumeURL string) (string, error)
}
