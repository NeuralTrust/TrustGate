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

type scriptedModelRequestPages struct {
	page      *appoauth.ModelRequestPage
	submitErr error
	gotTicket string
	gotReason string
}

func (s *scriptedModelRequestPages) CreateTicket(context.Context, appoauth.ModelRequestTicket) (string, error) {
	return "", nil
}

func (s *scriptedModelRequestPages) Page(_ context.Context, ticket string) (*appoauth.ModelRequestPage, error) {
	if ticket == "" {
		return nil, appoauth.ErrModelRequestLinkGone
	}
	return &appoauth.ModelRequestPage{Name: s.page.Name}, nil
}

func (s *scriptedModelRequestPages) Submit(_ context.Context, ticket, reason string) (*appoauth.ModelRequestPage, error) {
	s.gotTicket, s.gotReason = ticket, reason
	if s.submitErr != nil {
		return nil, s.submitErr
	}
	return s.page, nil
}

func modelRequestApp(h *ModelRequestHandler) *fiber.App {
	app := fiber.New()
	app.Get(appoauth.ModelRequestPagePath, h.Page)
	app.Post(appoauth.ModelRequestPagePath, h.Submit)
	return app
}

func doModelRequest(t *testing.T, app *fiber.App, method, target string, form url.Values) (int, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set(fiber.HeaderContentType, "application/x-www-form-urlencoded")
	}
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(raw)
}

func TestModelRequestPage_AsksWhyInThePersonsWords(t *testing.T) {
	t.Parallel()
	app := modelRequestApp(NewModelRequestHandler(&scriptedModelRequestPages{page: &appoauth.ModelRequestPage{Name: "Mistral"}}))

	status, body := doModelRequest(t, app, http.MethodGet, appoauth.ModelRequestPagePath+"?ticket=tkt-1", nil)

	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	for _, want := range []string{"Request access to Mistral models", `name="reason"`, "Send request"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page lacks %q:\n%s", want, body)
		}
	}
}

// The form posts the words under the field the service reads: a renamed field
// would file nothing while the page looked like it worked.
func TestModelRequestSubmit_ForwardsTheReasonAndConfirms(t *testing.T) {
	t.Parallel()
	pages := &scriptedModelRequestPages{page: &appoauth.ModelRequestPage{Name: "Mistral", Sent: true}}
	app := modelRequestApp(NewModelRequestHandler(pages))

	status, body := doModelRequest(t, app, http.MethodPost, appoauth.ModelRequestPagePath+"?ticket=tkt-1",
		url.Values{appoauth.ModelRequestReasonField: {"French support tickets"}})

	if status != http.StatusOK || pages.gotTicket != "tkt-1" || pages.gotReason != "French support tickets" {
		t.Fatalf("status = %d, ticket = %q, reason = %q", status, pages.gotTicket, pages.gotReason)
	}
	if !strings.Contains(body, "Sent. An administrator has to approve it") || strings.Contains(body, "<textarea") {
		t.Fatalf("a sent request confirms and offers no form:\n%s", body)
	}
}

func TestModelRequestSubmit_SaysWhatTheConsoleRefused(t *testing.T) {
	t.Parallel()
	pages := &scriptedModelRequestPages{page: &appoauth.ModelRequestPage{Name: "Mistral", Notice: "You already have access to Mistral models", Closed: true}}
	_, body := doModelRequest(t, modelRequestApp(NewModelRequestHandler(pages)), http.MethodPost,
		appoauth.ModelRequestPagePath+"?ticket=tkt-1", url.Values{appoauth.ModelRequestReasonField: {"x"}})
	if !strings.Contains(body, "You already have access to Mistral models") || strings.Contains(body, "<textarea") {
		t.Fatalf("body:\n%s", body)
	}
}

func TestModelRequestSubmit_WithoutAReasonShowsTheFormAgain(t *testing.T) {
	t.Parallel()
	pages := &scriptedModelRequestPages{page: &appoauth.ModelRequestPage{Name: "Mistral"}, submitErr: appoauth.ErrModelRequestReasonRequired}
	status, body := doModelRequest(t, modelRequestApp(NewModelRequestHandler(pages)), http.MethodPost,
		appoauth.ModelRequestPagePath+"?ticket=tkt-1", url.Values{appoauth.ModelRequestReasonField: {" "}})
	if status != http.StatusOK || !strings.Contains(body, "Tell the administrator why you need these models.") || !strings.Contains(body, "<textarea") {
		t.Fatalf("status = %d, body:\n%s", status, body)
	}
}

func TestModelRequestPage_ASpentLinkIsUnauthorized(t *testing.T) {
	t.Parallel()
	pages := &scriptedModelRequestPages{page: &appoauth.ModelRequestPage{Name: "Mistral"}, submitErr: appoauth.ErrModelRequestLinkGone}
	app := modelRequestApp(NewModelRequestHandler(pages))
	if status, _ := doModelRequest(t, app, http.MethodGet, appoauth.ModelRequestPagePath, nil); status != http.StatusUnauthorized {
		t.Fatalf("GET without a ticket = %d", status)
	}
	if status, _ := doModelRequest(t, app, http.MethodPost, appoauth.ModelRequestPagePath+"?ticket=old",
		url.Values{appoauth.ModelRequestReasonField: {"x"}}); status != http.StatusUnauthorized {
		t.Fatalf("POST on a spent link = %d", status)
	}
}
