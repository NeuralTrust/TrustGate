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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

func registerViaHTTP(t *testing.T, app *fiber.App, name string) appoauth.RegisterResponse {
	t.Helper()
	body := strings.NewReader(`{"redirect_uris":["https://` + name + `.example.com/cb"],"client_name":"` + name + `"}`)
	req := httptest.NewRequest(fiber.MethodPost, RegisterPath, body)
	req.Host = "gw.example.com"
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	if res.StatusCode != fiber.StatusCreated {
		t.Fatalf("register %s: status = %d", name, res.StatusCode)
	}
	var out appoauth.RegisterResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	return out
}

func manage(t *testing.T, app *fiber.App, method, clientID, token, body string) *http.Response {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, RegisterPath+"/"+clientID, reader)
	req.Host = "gw.example.com"
	if token != "" {
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+token)
	}
	if body != "" {
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	}
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, clientID, err)
	}
	return res
}

// TestRegisterHandlerReturnsAManagementURI is the defect-13 contract: a client
// that registers itself gets an address and a credential it can come back with.
// Before RUN-1501 the response carried neither, so QA had no way to withdraw a
// client it had registered.
func TestRegisterHandlerReturnsAManagementURI(t *testing.T) {
	t.Parallel()
	app := newTestApp(oauth2Auth("https://idp.example.com", "mcp-public-client"))

	out := registerViaHTTP(t, app, "cursor")

	if out.RegistrationAccessToken == "" {
		t.Fatal("registration_access_token missing from the registration response")
	}
	want := "http://gw.example.com" + RegisterPath + "/" + out.ClientID
	if out.RegistrationClientURI != want {
		t.Fatalf("registration_client_uri = %q, want %q", out.RegistrationClientURI, want)
	}
}

func TestRegisterHandlerManagementRoundTrip(t *testing.T) {
	t.Parallel()
	app := newTestApp(oauth2Auth("https://idp.example.com", "mcp-public-client"))
	out := registerViaHTTP(t, app, "cursor")

	read := manage(t, app, fiber.MethodGet, out.ClientID, out.RegistrationAccessToken, "")
	if read.StatusCode != fiber.StatusOK {
		t.Fatalf("read: status = %d, want 200 (the management URI must beat the catch-all GET)", read.StatusCode)
	}
	var got appoauth.RegisterResponse
	if err := json.NewDecoder(read.Body).Decode(&got); err != nil {
		t.Fatalf("decode read: %v", err)
	}
	if got.ClientID != out.ClientID || got.ClientName != "cursor" {
		t.Fatalf("read returned %+v", got)
	}

	updated := manage(t, app, fiber.MethodPut, out.ClientID, out.RegistrationAccessToken,
		`{"client_id":"`+out.ClientID+`","redirect_uris":["https://cursor.example.com/cb2"],"client_name":"Renamed"}`)
	if updated.StatusCode != fiber.StatusOK {
		t.Fatalf("update: status = %d, want 200", updated.StatusCode)
	}

	deleted := manage(t, app, fiber.MethodDelete, out.ClientID, out.RegistrationAccessToken, "")
	if deleted.StatusCode != fiber.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204 (the management URI must beat the catch-all DELETE)", deleted.StatusCode)
	}

	gone := manage(t, app, fiber.MethodGet, out.ClientID, out.RegistrationAccessToken, "")
	if gone.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("read after delete: status = %d, want 401", gone.StatusCode)
	}
}

func TestRegisterHandlerManagementRejectsBadCredentials(t *testing.T) {
	t.Parallel()
	app := newTestApp(oauth2Auth("https://idp.example.com", "mcp-public-client"))
	victim := registerViaHTTP(t, app, "victim")
	attacker := registerViaHTTP(t, app, "attacker")

	tests := map[string]string{
		"no authorization header": "",
		"a made-up token":         "gwrat_deadbeef",
		"another client's token":  attacker.RegistrationAccessToken,
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			for _, method := range []string{fiber.MethodGet, fiber.MethodDelete} {
				res := manage(t, app, method, victim.ClientID, token, "")
				if res.StatusCode != fiber.StatusUnauthorized {
					t.Fatalf("%s with %s: status = %d, want 401", method, name, res.StatusCode)
				}
			}
			res := manage(t, app, fiber.MethodPut, victim.ClientID, token,
				`{"redirect_uris":["https://attacker.example.com/steal"]}`)
			if res.StatusCode != fiber.StatusUnauthorized {
				t.Fatalf("PUT with %s: status = %d, want 401", name, res.StatusCode)
			}
		})
	}

	// The victim must still be readable with its own token afterwards.
	res := manage(t, app, fiber.MethodGet, victim.ClientID, victim.RegistrationAccessToken, "")
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("the victim registration must be intact, got %d", res.StatusCode)
	}
}

func TestRegisterHandlerUpdateRejectsMismatchedClientID(t *testing.T) {
	t.Parallel()
	app := newTestApp(oauth2Auth("https://idp.example.com", "mcp-public-client"))
	out := registerViaHTTP(t, app, "cursor")

	res := manage(t, app, fiber.MethodPut, out.ClientID, out.RegistrationAccessToken,
		`{"client_id":"agw-someone-else","redirect_uris":["https://cursor.example.com/cb2"]}`)
	if res.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a body naming another client", res.StatusCode)
	}
}

func TestRegisterHandlerManagementRejectsUnsafeRedirects(t *testing.T) {
	t.Parallel()
	app := newTestApp(oauth2Auth("https://idp.example.com", "mcp-public-client"))
	out := registerViaHTTP(t, app, "cursor")

	res := manage(t, app, fiber.MethodPut, out.ClientID, out.RegistrationAccessToken,
		`{"redirect_uris":["http://attacker.example.com/cb"]}`)
	if res.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-loopback http redirect", res.StatusCode)
	}
}
