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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// enrollingConnectService is a connect service that also takes header values.
type enrollingConnectService struct {
	*stubConnectService
	saved   map[string]string
	removed bool
}

func (s *enrollingConnectService) SaveUserHeaders(_ context.Context, _, _ string, values map[string]string) error {
	s.saved = values
	return nil
}

func (s *enrollingConnectService) RemoveUserHeaders(context.Context, string, string) error {
	s.removed = true
	return nil
}

func userHeaderPage(code string) *appoauth.ConnectPage {
	return &appoauth.ConnectPage{
		ConsumerPath: "/dev/mcp",
		Code:         code,
		Principal:    appoauth.ConnectPrincipal{Subject: "ana", Email: "ana@acme.test"},
		UserHeaders: []appoauth.UserHeaderServer{{
			Registry: "Keyed API", Instance: "inst-1",
			Fields: []appoauth.UserHeaderField{
				{Name: "X-API-Key", Required: true, Secret: true, Set: true},
				{Name: "X-Account", Value: "acct-visible", Set: true},
			},
		}},
	}
}

func TestConnectPage_ShowsPerUserHeaderForms(t *testing.T) {
	t.Parallel()
	for name, code := range map[string]string{"grid": "", "focused on a header-only server": "com.keyed/mcp"} {
		h := newTestConnectHandler(&stubConnectService{page: userHeaderPage(code)}, nil, "")
		h.holdFor = 0
		_, body := send(t, connectFlowApp(h), httptest.NewRequest(fiber.MethodGet, "/dev/mcp/connect?ticket=abc", nil))
		if !strings.Contains(body, `action="/oauth/user-headers/inst-1?ticket=abc"`) {
			t.Fatalf("%s: no save form: %s", name, body)
		}
		if !strings.Contains(body, `type="password"`) || !strings.Contains(body, "acct-visible") {
			t.Fatalf("%s: secret must be a password field and the plain value shown: %s", name, body)
		}
		if strings.Contains(body, "No third-party providers") {
			t.Fatalf("%s: a page with header servers says there is nothing to connect", name)
		}
	}
}

func TestSaveUserHeaders_OnlyFromTheGatewaysOwnPage(t *testing.T) {
	t.Parallel()
	svc := &enrollingConnectService{stubConnectService: &stubConnectService{page: userHeaderPage("")}}
	h := newTestConnectHandler(svc, nil, "")
	h.holdFor = 0
	app := fiber.New()
	app.Post(UserHeadersSavePath, h.SaveUserHeaders)
	app.Post(UserHeadersRemovePath, h.RemoveUserHeaders)

	cross := httptest.NewRequest(fiber.MethodPost, "/oauth/user-headers/inst-1?ticket=abc", strings.NewReader("X-API-Key=k"))
	cross.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationForm)
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	if res, _ := send(t, app, cross); res.StatusCode == fiber.StatusOK || svc.saved != nil {
		t.Fatalf("a cross-site post was accepted (status %d)", res.StatusCode)
	}

	own := httptest.NewRequest(fiber.MethodPost, "/oauth/user-headers/inst-1?ticket=abc", strings.NewReader("X-API-Key=k&X-Account=a"))
	own.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationForm)
	own.Header.Set("Sec-Fetch-Site", "same-origin")
	res, body := send(t, app, own)
	if res.StatusCode != fiber.StatusOK || svc.saved["X-API-Key"] != "k" {
		t.Fatalf("own-page save failed: %d %v", res.StatusCode, svc.saved)
	}
	if strings.Contains(body, `value="k"`) {
		t.Fatal("the saved secret was echoed into the page")
	}

	remove := httptest.NewRequest(fiber.MethodPost, "/oauth/user-headers-remove/inst-1?ticket=abc", nil)
	remove.Header.Set("Sec-Fetch-Site", "same-origin")
	if res, _ := send(t, app, remove); res.StatusCode != fiber.StatusOK || !svc.removed {
		t.Fatalf("remove failed: %d", res.StatusCode)
	}
}

// A focused page for a server whose only credential is its keys is not
// waiting for the server: it is here, with nothing to connect.
func TestConnectPage_HeaderOnlyServerDoesNotWait(t *testing.T) {
	t.Parallel()
	h := newTestConnectHandler(&stubConnectService{page: userHeaderPage("com.keyed/mcp")}, nil, "")
	h.holdFor = time.Minute
	started := time.Now()
	_, body := send(t, connectFlowApp(h), httptest.NewRequest(fiber.MethodGet, "/dev/mcp/connect?ticket=abc", nil))
	if time.Since(started) > 5*time.Second {
		t.Fatalf("the page waited for a server that is already here")
	}
	if !strings.Contains(body, "/oauth/user-headers/inst-1") {
		t.Fatalf("no key form: %s", body)
	}
}
