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
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/gofiber/fiber/v2"
)

type fakeCredentialFinder struct {
	oauth2 []*authdomain.Auth
}

func (f *fakeCredentialFinder) OAuth2Auths(context.Context) ([]*authdomain.Auth, error) {
	return f.oauth2, nil
}

func (f *fakeCredentialFinder) MTLSAuths(context.Context) ([]*authdomain.Auth, error) {
	return nil, nil
}

type memFlowStore struct {
	clients map[string]appoauth.RegisteredGatewayClient
}

func newMemFlowStore() *memFlowStore {
	return &memFlowStore{clients: map[string]appoauth.RegisteredGatewayClient{}}
}

func (s *memFlowStore) SavePending(context.Context, string, appoauth.PendingAuthorization) error {
	return nil
}

func (s *memFlowStore) TakePending(context.Context, string) (*appoauth.PendingAuthorization, error) {
	return nil, nil
}

func (s *memFlowStore) SaveCode(context.Context, string, appoauth.CodeGrant) error { return nil }

func (s *memFlowStore) TakeCode(context.Context, string) (*appoauth.CodeGrant, error) {
	return nil, nil
}

func (s *memFlowStore) SaveGatewayClient(_ context.Context, c appoauth.RegisteredGatewayClient) error {
	s.clients[c.ClientID] = c
	return nil
}

func (s *memFlowStore) GetGatewayClient(_ context.Context, id string) (*appoauth.RegisteredGatewayClient, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

func newTestApp(auths ...*authdomain.Auth) *fiber.App {
	svc := appoauth.NewMetadataService(&fakeCredentialFinder{oauth2: auths}, nil, nil, newMemFlowStore())
	app := fiber.New()
	pr := NewProtectedResourceHandler(svc)
	app.Get(WellKnownProtectedResourcePath, pr.Handle)
	app.Get(WellKnownProtectedResourcePath+"/*", pr.Handle)
	app.Get(WellKnownAuthorizationServerPath, NewAuthorizationServerHandler(svc).Handle)
	app.Post(RegisterPath, NewRegisterHandler(svc).Handle)
	return app
}

func oauth2Auth(issuer, clientID string) *authdomain.Auth {
	return &authdomain.Auth{Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
		Issuer:   issuer,
		JWKSURL:  issuer + "/jwks",
		ClientID: clientID,
	}}}
}

func TestProtectedResourceHandlerRootAndPathScoped(t *testing.T) {
	t.Parallel()
	app := newTestApp(oauth2Auth("https://idp.example.com", ""))

	for path, wantResource := range map[string]string{
		"/.well-known/oauth-protected-resource":            "http://gw.example.com",
		"/.well-known/oauth-protected-resource/v1/mcp/dev": "http://gw.example.com/v1/mcp/dev",
	} {
		res, err := app.Test(httptest.NewRequest(fiber.MethodGet, "http://gw.example.com"+path, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.StatusCode != fiber.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, res.StatusCode)
		}
		var meta appoauth.ProtectedResourceMetadata
		if err := json.NewDecoder(res.Body).Decode(&meta); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if meta.Resource != wantResource {
			t.Fatalf("%s: expected resource %q, got %q", path, wantResource, meta.Resource)
		}
		if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "http://gw.example.com" {
			t.Fatalf("%s: unexpected authorization_servers %v", path, meta.AuthorizationServers)
		}
	}
}

func TestAuthorizationServerHandlerNotFoundWithoutIssuer(t *testing.T) {
	t.Parallel()
	app := newTestApp()
	res, err := app.Test(httptest.NewRequest(fiber.MethodGet, "http://gw.example.com"+WellKnownAuthorizationServerPath, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StatusCode != fiber.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestRegisterHandler(t *testing.T) {
	t.Parallel()
	app := newTestApp(oauth2Auth("https://idp.example.com", "mcp-public-client"))

	body := strings.NewReader(`{"redirect_uris":["http://127.0.0.1:33418/callback"],"client_name":"Cursor"}`)
	req := httptest.NewRequest(fiber.MethodPost, "http://gw.example.com"+RegisterPath, body)
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StatusCode != fiber.StatusCreated {
		t.Fatalf("expected 201, got %d", res.StatusCode)
	}
	var out appoauth.RegisterResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(out.ClientID, "agw-") {
		t.Fatalf("expected gateway-issued client_id, got %q", out.ClientID)
	}
}

func TestRegisterHandlerUnavailable(t *testing.T) {
	t.Parallel()
	app := newTestApp(oauth2Auth("https://idp.example.com", ""))

	req := httptest.NewRequest(fiber.MethodPost, "http://gw.example.com"+RegisterPath, strings.NewReader(`{}`))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.StatusCode)
	}
}
