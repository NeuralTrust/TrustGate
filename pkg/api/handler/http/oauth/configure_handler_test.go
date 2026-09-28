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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
)

// recordingConfigure captures what the handler hands the service, so the form
// wiring can be checked without the service behind it.
type recordingConfigure struct {
	gotTicket string
	gotValues map[string]string
	page      *appoauth.ConfigurePage
}

func (r *recordingConfigure) CreateTicket(context.Context, appoauth.ConfigureTicketRequest) (string, error) {
	return "", nil
}

func (r *recordingConfigure) Page(context.Context, string) (*appoauth.ConfigurePage, error) {
	return r.page, nil
}

func (r *recordingConfigure) Submit(
	_ context.Context,
	ticketID string,
	values map[string]string,
) (*appoauth.ConfigurePage, error) {
	r.gotTicket = ticketID
	r.gotValues = values
	return r.page, nil
}

func postForm(t *testing.T, h *ConfigureHandler, target string, form url.Values) *http.Response {
	t.Helper()
	app := fiber.New()
	app.Post("/configure", h.Submit)
	req := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	req.Header.Set(fiber.HeaderContentType, "application/x-www-form-urlencoded")
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return res
}

// The request form posts the requester's words under a reserved field name, and
// the browser is the only thing that fills it in. The service tests call Submit
// with a map, so nothing covered the form body reaching it — a renamed field
// would have filed no request while the page looked like it worked.
func TestConfigureSubmit_ForwardsTheReasonFieldVerbatim(t *testing.T) {
	t.Parallel()
	svc := &recordingConfigure{page: &appoauth.ConfigurePage{Code: "com.notion/mcp", Saved: true, Pending: true}}
	h := NewConfigureHandler(svc)

	res := postForm(t, h, "/configure?ticket=tkt-1", url.Values{
		appoauth.ReasonFormField: {"I need Notion for the launch checklist"},
		"database":               {"analytics"},
	})
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, body = %s", res.StatusCode, body)
	}
	if svc.gotTicket != "tkt-1" {
		t.Fatalf("ticket = %q, want the one on the query string", svc.gotTicket)
	}
	if got := svc.gotValues[appoauth.ReasonFormField]; got != "I need Notion for the launch checklist" {
		t.Fatalf("reason = %q, want the words the form posted", got)
	}
	if got := svc.gotValues["database"]; got != "analytics" {
		t.Fatalf("catalog variables must travel too, got %q", got)
	}
}

func TestConfigureSubmit_RefusesABodyThatIsNotAForm(t *testing.T) {
	t.Parallel()
	svc := &recordingConfigure{page: &appoauth.ConfigurePage{}}
	h := NewConfigureHandler(svc)

	app := fiber.New()
	app.Post("/configure", h.Submit)
	req := httptest.NewRequest("POST", "/configure?ticket=tkt-1", strings.NewReader(`{"__reason":"x"}`))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.StatusCode != fiber.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", res.StatusCode)
	}
	if svc.gotValues != nil {
		t.Fatal("nothing may reach the service from a body it cannot parse")
	}
}

func TestConfigureSubmit_WithoutATicketNeverReachesTheService(t *testing.T) {
	t.Parallel()
	svc := &recordingConfigure{page: &appoauth.ConfigurePage{}}
	h := NewConfigureHandler(svc)

	res := postForm(t, h, "/configure", url.Values{appoauth.ReasonFormField: {"why"}})

	if res.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	if svc.gotValues != nil {
		t.Fatal("a ticketless submit must file nothing")
	}
}
