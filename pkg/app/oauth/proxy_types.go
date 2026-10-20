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

// The error code stays because identity providers need it to be told apart
// (invalid_grant, invalid_client); the free-text description is attacker
// controlled when the provider is tenant-chosen, so it is cut short and stripped
// of control characters before it is reflected.
const (
	maxUpstreamErrorCodeLen = 64
	maxUpstreamErrorDescLen = 200
)

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
	// AuthorizeURL is the identity provider redirect released by Approve.
	AuthorizeURL string `json:"authorize_url,omitempty"`
	// Approved is set by Approve; Callback redeems nothing that lacks it.
	Approved bool `json:"approved,omitempty"`
	// BrowserSignIn marks a sign-in the gateway started for one of its own
	// pages (see BrowserSignIn): its callback leaves a proof of who signed in
	// at RedirectURI instead of a code for a client.
	BrowserSignIn bool `json:"browser_sign_in,omitempty"`
	// Tenant is the tenant of the gateway a browser sign-in was started on, so
	// its callback refuses a person of another organization, as the MCP plane
	// refuses their session. Empty on a gateway with no tenant.
	Tenant string `json:"tenant,omitempty"`
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
	// BrowserSignIn marks a proof of a browser sign-in rather than a code: it
	// names who signed in for one of the gateway's own pages, and the token
	// endpoint never exchanges it.
	BrowserSignIn bool `json:"browser_sign_in,omitempty"`
	// IssuedAt is when this code was issued, which is the login. Exchange
	// copies it onto the session as LoginAt, so a revocation recorded after
	// the login still covers the code. Zero is a code stored before the field
	// existed; a marker then treats the login as missing and refuses it.
	IssuedAt time.Time `json:"issued_at,omitempty"`
}

type SessionRecord struct {
	// ClientID is the OAuth client the session was issued to, carried into
	// every refreshed token so the app it names survives a refresh.
	ClientID  string   `json:"client_id,omitempty"`
	Subject   string   `json:"subject"`
	Email     string   `json:"email,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	GatewayID string   `json:"gateway_id"`
	AuthID    string   `json:"auth_id"`
	Org       string   `json:"org,omitempty"`
	// Groups is the effective membership minted into the session: the login
	// claim union the directory list last pushed for this subject. Until the
	// first push it is the login snapshot. A push never removes a name that
	// was in that claim; such a name stays until the next login.
	Groups []string `json:"groups,omitempty"`
	// ClaimGroups is the platform token's groups claim, copied once at the
	// code exchange. It is not rewritten by a directory push.
	ClaimGroups []string `json:"claim_groups,omitempty"`
	// ClaimSnapshot reports that ClaimGroups was recorded at login. A record
	// from before that field existed has it false, and the first directory
	// push treats Groups as that snapshot.
	ClaimSnapshot bool     `json:"claim_snapshot,omitempty"`
	StoreAccess   string   `json:"store_access,omitempty"`
	Audiences     []string `json:"audiences,omitempty"`
	// LoginAt is when the user last authenticated at the identity provider. The
	// claims above are a snapshot taken at that moment; a refresh re-mints them
	// without consulting the IdP.
	LoginAt time.Time `json:"login_at,omitempty"`
	// ExpiresAt is the end of the session. With an absolute lifetime it is
	// fixed at login as LoginAt plus that lifetime; without one, each refresh
	// moves it a full idle window ahead. A refresh past it is refused so the
	// client re-runs the authorization and the claims are re-derived, and the
	// store expires the record here. A zero value (a record written before this
	// field existed) counts as expired.
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
	// GetCode reads a code grant without consuming it. A missing code is a nil
	// grant and a nil error. TakeCode is the single use, and it stays atomic.
	GetCode(ctx context.Context, code string) (*CodeGrant, error)
	TakeCode(ctx context.Context, code string) (*CodeGrant, error)
	SaveGatewayClient(ctx context.Context, c RegisteredGatewayClient) error
	GetGatewayClient(ctx context.Context, clientID string) (*RegisteredGatewayClient, error)
	DeleteGatewayClient(ctx context.Context, clientID string) error
	// SaveSession persists the record until rec.ExpiresAt, and only until then:
	// whether a rotated record's deadline moves is the proxy's decision, made
	// in rec.ExpiresAt, never the store's.
	SaveSession(ctx context.Context, refreshToken string, rec SessionRecord) error
	GetSession(ctx context.Context, refreshToken string) (*SessionRecord, error)
	// RetireSession shortens the session's remaining lifetime to the grace
	// window instead of deleting it. A rotated refresh token must survive
	// briefly: MCP clients refresh from several workers at once and retry when
	// a token response is lost in transit, and a hard single-use token turns
	// either into invalid_grant — killing the whole session. It must only ever
	// shorten the TTL, so replaying an old token cannot keep it alive.
	RetireSession(ctx context.Context, refreshToken string, grace time.Duration) error
	// SubjectRevokedAt is the instant this subject's default-IdP sessions were
	// revoked, or the zero time when no marker is stored. A store error is
	// returned rather than the zero time, so the caller can fail the refresh
	// the same way a failed session load fails it.
	SubjectRevokedAt(ctx context.Context, gatewayID, org, subject string) (time.Time, error)
	// DeleteSession removes one refresh record and its owner-index entry.
	// A token that is already gone is success.
	DeleteSession(ctx context.Context, refreshToken string) error
}

// SnapshotRevocations is the revocation marker in the config snapshot a data
// plane is serving. RevokedAt reports it, or false when that snapshot has no
// marker for the subject. A snapshot that is not loaded reports false: that
// is not a revocation. A Redis error reading the process-local marker stays
// the fail-closed path.
//
// Field 15 of the snapshot carries these rows. A data plane built before
// that field ignores it and keeps serving; the revocation applies once that
// plane runs a build that reads the field. Shipping the field does not block
// a deploy of older data planes.
type SnapshotRevocations interface {
	RevokedAt(gatewayID, org, subject string) (time.Time, bool)
}

// SubjectSessions revokes the default identity provider's refresh records for
// one subject. Personal keys, grants and other identity providers are not its
// concern.
type SubjectSessions interface {
	// RevokeSubjectSessions removes the default-IdP refresh records for org,
	// gatewayID and subject and drops their owner-index entries. Records for
	// another org, gateway, subject or identity provider stay. No matching
	// record is success and returns 0.
	RevokeSubjectSessions(ctx context.Context, org, gatewayID, subject string) (int, error)
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

// AuthorizeResult is where an authorization request goes next. With
// ConsentState set, the request is parked under that state until Approve or
// Deny, and Location is the identity provider redirect it waits on; otherwise
// Location returns to the client.
type AuthorizeResult struct {
	Location     string
	ConsentState string
}

type AuthProxy interface {
	Authorize(ctx context.Context, baseURL string, req AuthorizeRequest) (AuthorizeResult, error)
	Approve(ctx context.Context, state string) (string, error)
	Deny(ctx context.Context, state string) (string, error)
	Callback(ctx context.Context, baseURL, state, code, idpErr, idpErrDesc string) (string, error)
	Exchange(ctx context.Context, baseURL string, req TokenRequest) (map[string]any, error)
}
