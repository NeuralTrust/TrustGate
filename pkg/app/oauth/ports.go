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

type ProviderToken struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	Scopes       []string
	ExpiresAt    time.Time
}

//go:generate mockery --name=ProviderClient --dir=. --output=./mocks --filename=oauth_provider_client_mock.go --case=underscore --with-expecter
type ProviderClient interface {
	AuthorizeURL(cfg *registrydomain.MCPAuth, redirectURI, state, challenge string) string
	ExchangeCode(ctx context.Context, cfg *registrydomain.MCPAuth, code, redirectURI, verifier string) (*ProviderToken, error)
	Refresh(ctx context.Context, cfg *registrydomain.MCPAuth, refreshToken string) (*ProviderToken, error)
	ClientCredentials(ctx context.Context, cfg *registrydomain.MCPAuth) (*ProviderToken, error)
}

// ErrUpstreamRegistrationRejected: the upstream authorization server refused
// the dynamic client registration. It is the upstream's answer, not a gateway
// fault, so callers report it as a bad gateway rather than a 500.
var ErrUpstreamRegistrationRejected = errors.New("oauth dcr: registration rejected")

var ErrUpstreamNotDiscoverable = errors.New(
	"oauth dcr: upstream does not publish OAuth protected-resource metadata; configure registration: manual with a pre-registered OAuth app")

var ErrInvalidGrant = errors.New("oauth provider: grant is no longer valid")

// InvalidGrantError preserves provider diagnostics while supporting errors.Is.
type InvalidGrantError struct {
	Code        string
	Description string
}

// Error returns the grant failure without exposing provider response text.
func (e *InvalidGrantError) Error() string { return ErrInvalidGrant.Error() }

// Unwrap identifies the failure as ErrInvalidGrant.
func (e *InvalidGrantError) Unwrap() error { return ErrInvalidGrant }

// ErrInvalidClient is returned when a token endpoint rejects the client
// itself (invalid_client or unauthorized_client), as opposed to the grant.
var ErrInvalidClient = errors.New("oauth provider: client is not recognized")

// InvalidClientError preserves the provider's client-rejection code while
// supporting errors.Is.
type InvalidClientError struct {
	Code        string
	Description string
}

// Error returns the token failure with the provider's client-rejection code.
// The description is already capped and stripped of control characters.
func (e *InvalidClientError) Error() string {
	return "oauth provider: token exchange failed (" + e.Code + "): " + e.Description
}

// Unwrap identifies the failure as ErrInvalidClient.
func (e *InvalidClientError) Unwrap() error { return ErrInvalidClient }

type UpstreamAuthServer struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	// UserinfoEndpoint is where an OpenID provider answers who a token is for.
	// Optional in the metadata; when present, it names the account a
	// connection was made with (see resolveAccountRef).
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`
	// RevocationEndpoint is the RFC 7009 endpoint the authorization server
	// advertised. Empty when the provider does not support token revocation.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
	// ValidatedIssuer is the authorization-server URL the metadata was fetched
	// from, after that URL matched the document's issuer. It is not copied from
	// the document. Empty when Discover has not accepted the server. Cache keys
	// and revocation use it.
	ValidatedIssuer string   `json:"-"`
	ScopesSupported []string `json:"scopes_supported"`
	Resource        string   `json:"resource"`
}

type RegisteredClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURI  string `json:"redirect_uri"`
	// ClientName is the client_name the client was registered with. Empty on
	// rows written before the name became configurable (the default name).
	ClientName string `json:"client_name,omitempty"`
	// Issuer is the authorization server this client was registered with.
	// Empty on rows written before the server was recorded.
	Issuer string `json:"issuer,omitempty"`
	// RegistrationEndpoint is the dynamic-registration URL this client was
	// registered at. Empty on rows written before it was recorded.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	// ClientSecretExpiresAt is the RFC 7591 client_secret_expires_at, in
	// seconds since the epoch. Zero means the registration does not expire.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`
}

type ClientStore interface {
	SaveClient(ctx context.Context, key string, c RegisteredClient) error
	GetClient(ctx context.Context, key string) (*RegisteredClient, error)
	// SaveClientIfAbsent stores c only when no client is registered under key
	// yet, and returns whichever client ends up stored — c when this caller won
	// the claim, the incumbent when another replica got there first. Dynamic
	// client registration is not idempotent: two replicas registering
	// concurrently mint two client_ids, and the one that loses a last-write-wins
	// save takes every refresh token issued to it down with it.
	SaveClientIfAbsent(ctx context.Context, key string, c RegisteredClient) (*RegisteredClient, error)
	// ReplaceClientIfMatch stores next only when the client currently stored
	// under key has client_id expected. A missing row or a different client_id
	// is left as it is. swapped is false when nothing was written; stored is
	// the client left in the slot, or nil when the slot is empty.
	ReplaceClientIfMatch(ctx context.Context, key, expectedClientID string, next RegisteredClient) (stored *RegisteredClient, swapped bool, err error)
}

//go:generate mockery --name=UpstreamRegistrar --dir=. --output=./mocks --filename=oauth_upstream_registrar_mock.go --case=underscore --with-expecter
type UpstreamRegistrar interface {
	Discover(ctx context.Context, upstreamURL string) (*UpstreamAuthServer, error)
	EnsureClient(ctx context.Context, key string, meta *UpstreamAuthServer, redirectURI string) (*RegisteredClient, error)
	CachedClient(ctx context.Context, key string) (*RegisteredClient, error)
	// DropCachedClient marks a cached dynamic client unusable so the next
	// EnsureClient replaces it, but only when the stored client_id is still
	// clientID. A row that has already been replaced is left alone. The stored
	// row is kept, so that replacement overwrites it (and logs) instead of
	// opening a fresh registration race.
	DropCachedClient(ctx context.Context, key, clientID string) error
}

// RegisteredClientDropper forgets a dynamic client the authorization server
// rejected. ConnectService implements it. clientID is the client the token
// endpoint refused; a cache row for a different client is left alone.
type RegisteredClientDropper interface {
	DropRegisteredClient(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry, clientID string) error
}
