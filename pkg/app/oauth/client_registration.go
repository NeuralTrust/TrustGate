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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	ErrClientNotFound        = errors.New("oauth: client registration not found")
	ErrRegistrationForbidden = errors.New("oauth: registration access token does not match this client")
)

const registrationTokenPrefix = "gwrat_" // #nosec G101 -- token name prefix, not a credential

// RegistrationClientURI returns the RFC 7592 management URI of a registration.
func RegistrationClientURI(baseURL, clientID string) string {
	return strings.TrimRight(baseURL, "/") + RegisterBasePath + "/" + url.PathEscape(clientID)
}

// RegisterBasePath is the dynamic client registration endpoint, and the parent
// of every client's own RFC 7592 management URI.
const RegisterBasePath = "/oauth/register"

func newRegistrationToken() (string, string, error) {
	suffix, err := randomToken()
	if err != nil {
		return "", "", err
	}
	token := registrationTokenPrefix + suffix
	return token, hashRegistrationToken(token), nil
}

func hashRegistrationToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// authorizeRegistration resolves the registration named in the path and checks
// the presented registration access token against that registration's own
// digest. Resolving by the path client id and comparing against only that
// client's digest is what stops one client managing another's registration: a
// token issued for a different client hashes to a different digest and fails
// here, whatever client id it names.
func (s *metadataService) authorizeRegistration(ctx context.Context, clientID, token string) (*RegisteredGatewayClient, error) {
	if s.clients == nil {
		return nil, ErrRegistrationUnavailable
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, ErrClientNotFound
	}
	client, err := s.clients.GetGatewayClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("oauth: load client registration: %w", err)
	}
	if client == nil {
		return nil, ErrClientNotFound
	}
	// A registration with no stored digest predates the management endpoints.
	// Comparing an empty digest would admit any caller, so it is refused
	// outright; the client re-registers to get a manageable registration.
	if client.RegistrationTokenHash == "" {
		return nil, ErrRegistrationForbidden
	}
	presented := hashRegistrationToken(strings.TrimSpace(token))
	if subtle.ConstantTimeCompare([]byte(presented), []byte(client.RegistrationTokenHash)) != 1 {
		return nil, ErrRegistrationForbidden
	}
	return client, nil
}

func (s *metadataService) ReadClient(ctx context.Context, baseURL, clientID, token string) (*RegisterResponse, error) {
	client, err := s.authorizeRegistration(ctx, clientID, token)
	if err != nil {
		return nil, err
	}
	return registrationResponse(baseURL, *client, ""), nil
}

// UpdateClient replaces the client metadata a dynamic registration may change.
// The registration access token is not rotated, so the client keeps the one it
// holds (RFC 7592 section 3.2), and the response omits it.
func (s *metadataService) UpdateClient(ctx context.Context, baseURL, clientID, token string, req RegisterRequest) (*RegisterResponse, error) {
	client, err := s.authorizeRegistration(ctx, clientID, token)
	if err != nil {
		return nil, err
	}
	if len(req.RedirectURIs) == 0 {
		return nil, oauthErr("invalid_client_metadata", "redirect_uris is required")
	}
	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		return nil, err
	}
	updated := *client
	updated.RedirectURIs = req.RedirectURIs
	updated.ClientName = req.ClientName
	if err := s.clients.SaveGatewayClient(ctx, updated); err != nil {
		return nil, fmt.Errorf("oauth: persist client registration: %w", err)
	}
	return registrationResponse(baseURL, updated, ""), nil
}

func (s *metadataService) DeleteClient(ctx context.Context, clientID, token string) error {
	if _, err := s.authorizeRegistration(ctx, clientID, token); err != nil {
		return err
	}
	if err := s.clients.DeleteGatewayClient(ctx, strings.TrimSpace(clientID)); err != nil {
		return fmt.Errorf("oauth: delete client registration: %w", err)
	}
	return nil
}

func validateRedirectURIs(uris []string) error {
	for _, uri := range uris {
		if !IsAcceptableRedirectURI(uri) {
			return oauthErr("invalid_redirect_uri",
				fmt.Sprintf("%q must be an https URL, an http loopback URL, or a private-use URI without a fragment", uri))
		}
	}
	return nil
}

// registrationResponse renders a stored registration. accessToken is set only
// on the registration that just minted it; a read or an update leaves it empty
// because only the digest is stored and the client already holds the token.
func registrationResponse(baseURL string, c RegisteredGatewayClient, accessToken string) *RegisterResponse {
	return &RegisterResponse{
		ClientID:                c.ClientID,
		RedirectURIs:            c.RedirectURIs,
		ClientName:              c.ClientName,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		RegistrationClientURI:   RegistrationClientURI(baseURL, c.ClientID),
		RegistrationAccessToken: accessToken,
	}
}
