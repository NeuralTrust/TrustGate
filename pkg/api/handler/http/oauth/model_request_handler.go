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
	"errors"
	"html/template"
	"net/url"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// ModelRequestHandler serves the MCP Store's model request page: the form,
// reached by a short-lived link from trustgate_store_request_models, where a
// person says why they need a provider's models. Sending it files the request
// in the console, where Access → Approvals decides it. The link authorizes the
// request for its owner; the browser itself is unauthenticated, exactly like
// the MCP request form.
type ModelRequestHandler struct {
	pages appoauth.ModelRequestPages
}

func NewModelRequestHandler(pages appoauth.ModelRequestPages) *ModelRequestHandler {
	return &ModelRequestHandler{pages: pages}
}

func (h *ModelRequestHandler) Page(c *fiber.Ctx) error {
	setConfigureResponsePolicies(c)
	page, err := h.pages.Page(c.UserContext(), c.Query("ticket"))
	if err != nil {
		return modelRequestError(c, err)
	}
	return renderModelRequestPage(c, page, "")
}

func (h *ModelRequestHandler) Submit(c *fiber.Ctx) error {
	setConfigureResponsePolicies(c)
	if !isFormURLEncoded(c.Get(fiber.HeaderContentType)) {
		return fiber.NewError(fiber.StatusUnsupportedMediaType, "expected application/x-www-form-urlencoded")
	}
	values, err := url.ParseQuery(string(c.Body()))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "malformed form body")
	}
	ticket := c.Query("ticket")
	page, err := h.pages.Submit(c.UserContext(), ticket, values.Get(appoauth.ModelRequestReasonField))
	if errors.Is(err, appoauth.ErrModelRequestReasonRequired) {
		// The form again, saying what is missing, rather than an error page.
		if page, perr := h.pages.Page(c.UserContext(), ticket); perr == nil {
			return renderModelRequestPage(c, page, "Tell the administrator why you need these models.")
		}
	}
	if err != nil {
		return modelRequestError(c, err)
	}
	return renderModelRequestPage(c, page, "")
}

func modelRequestError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, appoauth.ErrModelRequestLinkGone):
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	case errors.Is(err, appoauth.ErrModelRequestReasonRequired):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return err
}

type modelRequestPageView struct {
	Name           string
	Sent           bool
	Notice         string
	Closed         bool
	ReasonField    string
	ReasonMaxChars int
}

func renderModelRequestPage(c *fiber.Ctx, page *appoauth.ModelRequestPage, notice string) error {
	if notice == "" {
		notice = page.Notice
	}
	return renderHTML(c, modelRequestPageTmpl, modelRequestPageView{
		Name:           page.Name,
		Sent:           page.Sent,
		Notice:         notice,
		Closed:         page.Closed,
		ReasonField:    appoauth.ModelRequestReasonField,
		ReasonMaxChars: appoauth.MaxModelRequestReasonLength,
	})
}

const modelRequestCheckGlyph = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>`

const modelRequestInfoGlyph = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`

var modelRequestPageTmpl = template.Must(template.New("model-request").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
` + pageFonts + `
<title>Request {{.Name}} models - NeuralTrust TrustGate</title><style>` + pageCSS + `</style></head>
<body class="dotted"><div class="card">` + brandHeader + `
<h1>Request access to {{.Name}} models</h1>
<p class="sub">Asking for these models goes to an administrator. Tell them why you need them, in your own words — this is what they read when they decide. Once they approve, your personal key reaches the models.</p>
{{if .Sent}}<div class="flash" role="status">` + modelRequestCheckGlyph + `<div>Sent. An administrator has to approve it; you can return to your application.</div></div>
{{else if .Notice}}<div class="flash" role="status">` + modelRequestInfoGlyph + `<div>{{.Notice}}</div></div>{{end}}
{{if not (or .Sent .Closed)}}<form class="connect-form" method="post">
  <div class="input area">
    <textarea id="{{.ReasonField}}" name="{{.ReasonField}}" rows="4" maxlength="{{.ReasonMaxChars}}" autocomplete="off" required placeholder=" "></textarea>
    <label for="{{.ReasonField}}">Why do you need them?</label>
  </div>
  <button class="btn primary" type="submit">Send request</button>
</form>{{end}}
</div></body></html>`))
