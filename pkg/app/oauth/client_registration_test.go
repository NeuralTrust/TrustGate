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
	"strings"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

const testBaseURL = "https://gw.example.com"

func registrationService(t *testing.T) (MetadataService, *memFlowStore) {
	t.Helper()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: "https://idp.example.com", ClientID: "mcp-public-client"}),
	}}
	store := newMemFlowStore()
	return NewMetadataService(finder, nil, nil, store), store
}

func register(t *testing.T, svc MetadataService, name string) *RegisterResponse {
	t.Helper()
	res, err := svc.RegisterClient(context.Background(), testBaseURL, RegisterRequest{
		RedirectURIs: []string{"https://" + name + ".example.com/cb"},
		ClientName:   name,
	})
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	return res
}

func TestRegisterClientIssuesAManageableRegistration(t *testing.T) {
	t.Parallel()
	svc, store := registrationService(t)

	res := register(t, svc, "cursor")

	if res.RegistrationAccessToken == "" {
		t.Fatal("registration must return a registration_access_token")
	}
	if !strings.HasPrefix(res.RegistrationAccessToken, registrationTokenPrefix) {
		t.Fatalf("registration_access_token = %q, want the %q prefix", res.RegistrationAccessToken, registrationTokenPrefix)
	}
	want := testBaseURL + "/oauth/register/" + res.ClientID
	if res.RegistrationClientURI != want {
		t.Fatalf("registration_client_uri = %q, want %q", res.RegistrationClientURI, want)
	}
	// A public client has no secret, so it must not claim an expiry for one.
	if res.TokenEndpointAuthMethod != "none" {
		t.Fatalf("token_endpoint_auth_method = %q", res.TokenEndpointAuthMethod)
	}

	saved, err := store.GetGatewayClient(context.Background(), res.ClientID)
	if err != nil || saved == nil {
		t.Fatalf("expected a persisted registration: %v (err %v)", saved, err)
	}
	if saved.RegistrationTokenHash == "" {
		t.Fatal("the registration must persist a token digest")
	}
	if strings.Contains(saved.RegistrationTokenHash, res.RegistrationAccessToken) ||
		saved.RegistrationTokenHash == res.RegistrationAccessToken {
		t.Fatal("only the digest may be stored, never the registration access token itself")
	}
	if saved.RegistrationTokenHash != hashRegistrationToken(res.RegistrationAccessToken) {
		t.Fatal("stored digest must be the SHA-256 of the issued token")
	}
}

func TestReadClientRoundTripsMetadata(t *testing.T) {
	t.Parallel()
	svc, _ := registrationService(t)
	res := register(t, svc, "cursor")

	got, err := svc.ReadClient(context.Background(), testBaseURL, res.ClientID, res.RegistrationAccessToken)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.ClientID != res.ClientID || got.ClientName != "cursor" {
		t.Fatalf("read returned %+v", got)
	}
	if got.RegistrationClientURI != res.RegistrationClientURI {
		t.Fatalf("read must echo the management URI, got %q", got.RegistrationClientURI)
	}
	// Only the digest is stored, so the token cannot be handed back; RFC 7592
	// leaves the client using the one it already holds.
	if got.RegistrationAccessToken != "" {
		t.Fatal("a read must not return a registration access token")
	}
}

func TestRegistrationRejectsAWrongToken(t *testing.T) {
	t.Parallel()
	svc, _ := registrationService(t)
	res := register(t, svc, "cursor")

	tests := map[string]string{
		"an empty token":       "",
		"a bare prefix":        registrationTokenPrefix,
		"another random token": registrationTokenPrefix + strings.Repeat("a", 64),
		"the client id":        res.ClientID,
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.ReadClient(context.Background(), testBaseURL, res.ClientID, token); !errors.Is(err, ErrRegistrationForbidden) {
				t.Fatalf("read with %s: error = %v, want ErrRegistrationForbidden", name, err)
			}
			if err := svc.DeleteClient(context.Background(), res.ClientID, token); !errors.Is(err, ErrRegistrationForbidden) {
				t.Fatalf("delete with %s: error = %v, want ErrRegistrationForbidden", name, err)
			}
		})
	}
}

// TestRegistrationIsolatesClientsFromEachOther is the check QA's withdrawal
// scenario turns on: one self-registered client must not be able to read,
// rewrite or delete another's registration, even though both hold a valid
// registration access token of their own.
func TestRegistrationIsolatesClientsFromEachOther(t *testing.T) {
	t.Parallel()
	svc, store := registrationService(t)
	victim := register(t, svc, "victim")
	attacker := register(t, svc, "attacker")

	ctx := context.Background()
	if _, err := svc.ReadClient(ctx, testBaseURL, victim.ClientID, attacker.RegistrationAccessToken); !errors.Is(err, ErrRegistrationForbidden) {
		t.Fatalf("cross-client read: error = %v, want ErrRegistrationForbidden", err)
	}
	if _, err := svc.UpdateClient(ctx, testBaseURL, victim.ClientID, attacker.RegistrationAccessToken, RegisterRequest{
		RedirectURIs: []string{"https://attacker.example.com/steal"},
	}); !errors.Is(err, ErrRegistrationForbidden) {
		t.Fatalf("cross-client update: error = %v, want ErrRegistrationForbidden", err)
	}
	if err := svc.DeleteClient(ctx, victim.ClientID, attacker.RegistrationAccessToken); !errors.Is(err, ErrRegistrationForbidden) {
		t.Fatalf("cross-client delete: error = %v, want ErrRegistrationForbidden", err)
	}

	survived, err := store.GetGatewayClient(ctx, victim.ClientID)
	if err != nil || survived == nil {
		t.Fatalf("the victim registration must survive: %v (err %v)", survived, err)
	}
	if survived.RedirectURIs[0] != "https://victim.example.com/cb" {
		t.Fatalf("the victim redirect_uris must be untouched, got %v", survived.RedirectURIs)
	}
}

func TestUpdateClientReplacesMetadata(t *testing.T) {
	t.Parallel()
	svc, store := registrationService(t)
	res := register(t, svc, "cursor")

	got, err := svc.UpdateClient(context.Background(), testBaseURL, res.ClientID, res.RegistrationAccessToken, RegisterRequest{
		RedirectURIs: []string{"https://cursor.example.com/cb2"},
		ClientName:   "Cursor renamed",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.ClientName != "Cursor renamed" || got.RedirectURIs[0] != "https://cursor.example.com/cb2" {
		t.Fatalf("update returned %+v", got)
	}
	if got.ClientID != res.ClientID {
		t.Fatal("an update must not re-issue the client id")
	}

	saved, err := store.GetGatewayClient(context.Background(), res.ClientID)
	if err != nil || saved == nil {
		t.Fatalf("expected the updated registration: %v (err %v)", saved, err)
	}
	if saved.RedirectURIs[0] != "https://cursor.example.com/cb2" {
		t.Fatalf("persisted redirect_uris = %v", saved.RedirectURIs)
	}
	// The token is not rotated, so the client keeps working with the one it has.
	if saved.RegistrationTokenHash != hashRegistrationToken(res.RegistrationAccessToken) {
		t.Fatal("an update must not invalidate the registration access token")
	}
	if _, err := svc.ReadClient(context.Background(), testBaseURL, res.ClientID, res.RegistrationAccessToken); err != nil {
		t.Fatalf("the original token must still work after an update: %v", err)
	}
}

func TestUpdateClientValidatesRedirects(t *testing.T) {
	t.Parallel()
	svc, _ := registrationService(t)
	res := register(t, svc, "cursor")

	for _, uri := range []string{"http://attacker.example.com/cb", "javascript:alert(1)", "https://ok.example.com/cb#frag"} {
		if _, err := svc.UpdateClient(context.Background(), testBaseURL, res.ClientID, res.RegistrationAccessToken, RegisterRequest{
			RedirectURIs: []string{uri},
		}); err == nil {
			t.Fatalf("update must apply the same redirect rules as registration, accepted %q", uri)
		}
	}
	if _, err := svc.UpdateClient(context.Background(), testBaseURL, res.ClientID, res.RegistrationAccessToken, RegisterRequest{}); err == nil {
		t.Fatal("update without redirect_uris must be refused")
	}
}

func TestDeleteClientWithdrawsTheRegistration(t *testing.T) {
	t.Parallel()
	svc, store := registrationService(t)
	res := register(t, svc, "cursor")
	ctx := context.Background()

	if err := svc.DeleteClient(ctx, res.ClientID, res.RegistrationAccessToken); err != nil {
		t.Fatalf("delete: %v", err)
	}
	gone, err := store.GetGatewayClient(ctx, res.ClientID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if gone != nil {
		t.Fatalf("the registration must be gone, got %+v", gone)
	}
	if _, err := svc.ReadClient(ctx, testBaseURL, res.ClientID, res.RegistrationAccessToken); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("read after delete: error = %v, want ErrClientNotFound", err)
	}
}

// TestRegistrationRefusesAClientWithNoStoredDigest covers registrations written
// before RUN-1501 added the management endpoints. They carry no digest, and an
// empty digest must never compare equal to a presented token.
func TestRegistrationRefusesAClientWithNoStoredDigest(t *testing.T) {
	t.Parallel()
	svc, store := registrationService(t)
	ctx := context.Background()
	if err := store.SaveGatewayClient(ctx, RegisteredGatewayClient{
		ClientID:     "agw-legacy",
		RedirectURIs: []string{"https://legacy.example.com/cb"},
	}); err != nil {
		t.Fatalf("seed legacy client: %v", err)
	}

	for _, token := range []string{"", registrationTokenPrefix + "anything", hashRegistrationToken("")} {
		if _, err := svc.ReadClient(ctx, testBaseURL, "agw-legacy", token); !errors.Is(err, ErrRegistrationForbidden) {
			t.Fatalf("legacy read with %q: error = %v, want ErrRegistrationForbidden", token, err)
		}
		if err := svc.DeleteClient(ctx, "agw-legacy", token); !errors.Is(err, ErrRegistrationForbidden) {
			t.Fatalf("legacy delete with %q: error = %v, want ErrRegistrationForbidden", token, err)
		}
	}
}

func TestRegistrationOnAnUnknownClient(t *testing.T) {
	t.Parallel()
	svc, _ := registrationService(t)
	ctx := context.Background()

	if _, err := svc.ReadClient(ctx, testBaseURL, "agw-nope", registrationTokenPrefix+"x"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("read unknown: error = %v, want ErrClientNotFound", err)
	}
	if _, err := svc.ReadClient(ctx, testBaseURL, "", registrationTokenPrefix+"x"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("read with no client id: error = %v, want ErrClientNotFound", err)
	}
}
