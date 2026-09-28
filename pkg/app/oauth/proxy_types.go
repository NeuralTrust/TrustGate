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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const CallbackPath = "/oauth/callback"

type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func oauthErr(code, desc string) *OAuthError { return &OAuthError{Code: code, Description: desc} }

type PendingAuthorization struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Scope               string `json:"scope"`
	CodeVerifier        string `json:"code_verifier"`
	Resource            string `json:"resource,omitempty"`
	AuthID              string `json:"auth_id,omitempty"`
	// GatewayID is the gateway the addressed MCP consumer belongs to. It is
	// captured at authorize time so the built-in default identity provider —
	// which has no owning gateway of its own — can still bind the minted
	// session to the right gateway at callback time.
	GatewayID string `json:"gateway_id,omitempty"`
}

type CodeGrant struct {
	ClientID      string         `json:"client_id"`
	RedirectURI   string         `json:"redirect_uri"`
	CodeChallenge string         `json:"code_challenge"`
	Token         map[string]any `json:"token"`
	Subject       string         `json:"subject,omitempty"`
	Email         string         `json:"email,omitempty"`
	AuthID        string         `json:"auth_id,omitempty"`
	GatewayID     string         `json:"gateway_id,omitempty"`
	// Org is the platform tenant (team) the authenticated user belongs to,
	// captured from the identity provider token. It is bound into the minted
	// session so the MCP plane can enforce that a default-IdP login only reaches
	// gateways of that tenant.
	Org string `json:"org,omitempty"`
	// Groups are the user's IdP group memberships, propagated so role
	// oidc_mapping rules can match against them.
	Groups []string `json:"groups,omitempty"`
	// StoreAccess is the per-principal MCP Store access level ("open",
	// "curated" or "none") the control plane minted into the platform token.
	// It is carried into the gateway session so the Store tool can enforce the
	// admin's per-user decision; absent means the gateway's own Store default
	// mode applies.
	StoreAccess string   `json:"store_access,omitempty"`
	Audiences   []string `json:"audiences,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	SessionMode bool     `json:"session_mode,omitempty"`
}

type SessionRecord struct {
	Subject     string   `json:"subject"`
	Email       string   `json:"email,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	GatewayID   string   `json:"gateway_id"`
	AuthID      string   `json:"auth_id"`
	Org         string   `json:"org,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	StoreAccess string   `json:"store_access,omitempty"`
	Audiences   []string `json:"audiences,omitempty"`
	// LoginAt is when the user last authenticated at the identity provider. The
	// claims above are a snapshot taken at that moment; a refresh re-mints them
	// without consulting the IdP, so the snapshot must not live forever.
	LoginAt time.Time `json:"login_at,omitempty"`
	// ExpiresAt is the absolute end of the session, fixed at login as LoginAt
	// plus the session lifetime. A refresh past it is refused so the client
	// re-runs the authorization and the claims are re-derived, and the store
	// expires the record here instead of sliding its TTL on every rotation. A
	// zero value (a record written before this field existed) counts as expired.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type RegisteredGatewayClient struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name,omitempty"`
	// RegistrationTokenHash is the SHA-256 of the RFC 7592 registration access
	// token handed to the client once, at registration. Only the digest is kept:
	// the token authenticates management of this registration, so a Redis dump
	// must not be enough to read, rewrite or withdraw a customer's client. An
	// empty value belongs to a client registered before RUN-1501 added the
	// management endpoints and can never be managed through them.
	RegistrationTokenHash string `json:"registration_token_hash,omitempty"`
}

type FlowStore interface {
	SavePending(ctx context.Context, state string, p PendingAuthorization) error
	TakePending(ctx context.Context, state string) (*PendingAuthorization, error)
	SaveCode(ctx context.Context, code string, g CodeGrant) error
	TakeCode(ctx context.Context, code string) (*CodeGrant, error)
	SaveGatewayClient(ctx context.Context, c RegisteredGatewayClient) error
	GetGatewayClient(ctx context.Context, clientID string) (*RegisteredGatewayClient, error)
	DeleteGatewayClient(ctx context.Context, clientID string) error
	// SaveSession persists the record until rec.ExpiresAt. Saving a rotated
	// record again must not extend that deadline: the session's lifetime is
	// fixed at login, not renewed by use.
	SaveSession(ctx context.Context, refreshToken string, rec SessionRecord) error
	GetSession(ctx context.Context, refreshToken string) (*SessionRecord, error)
	// RetireSession shortens the session's remaining lifetime to the grace
	// window instead of deleting it. A rotated refresh token must survive
	// briefly: MCP clients refresh from several workers at once and retry when
	// a token response is lost in transit, and a hard single-use token turns
	// either into invalid_grant — killing the whole session. It must only ever
	// shorten the TTL, so replaying an old token cannot keep it alive.
	RetireSession(ctx context.Context, refreshToken string, grace time.Duration) error
}

type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	RefreshToken string
	Resource     string
}

type ConsentChainer interface {
	ChainURL(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, principalSub, resumeURL string) (string, error)
}

type AuthProxy interface {
	Authorize(ctx context.Context, baseURL string, req AuthorizeRequest) (string, error)
	Callback(ctx context.Context, baseURL, state, code, idpErr, idpErrDesc string) (string, error)
	Exchange(ctx context.Context, baseURL string, req TokenRequest) (map[string]any, error)
}
