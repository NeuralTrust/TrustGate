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

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

// StorePersonalKeyToolName hands the user the page where they create their
// personal key.
const StorePersonalKeyToolName = StoreToolNamePrefix + "personal_key"

// PersonalKeyLinks mints the ticket a personal key page link carries.
// appoauth.PersonalKeyPages satisfies it.
type PersonalKeyLinks interface {
	CreateTicket(ctx context.Context, ticket appoauth.PersonalKeyTicket) (string, error)
}

// WithStoreToolPersonalKeys offers the personal key tool. proxyDomain is the
// LLM plane's base domain, for the models the key reaches.
func WithStoreToolPersonalKeys(links PersonalKeyLinks, proxyDomain string) StoreToolOption {
	return func(t *storeTool) {
		t.personalKeys = links
		t.proxyDomain = proxyDomain
	}
}

// personalKey answers the tool: a link to the page, never the key. The key is
// shown to the person in their browser, once, after they sign in there; a
// model that saw it would hold a credential that acts as them.
func (t *storeTool) personalKey(ctx context.Context, rc *appconsumer.RoutableConsumer, baseURL string) (json.RawMessage, error) {
	if t.personalKeys == nil {
		return nil, fmt.Errorf("%w: personal keys are not available here", ErrStoreToolUnavailable)
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return nil, ErrNoPrincipal
	}
	gw, _ := appgateway.FromContext(ctx)
	if gw != nil && !gw.AllowsPersonal() {
		return marshalToolResult(
			"Personal keys are not available on this gateway: it runs on the organisation's own infrastructure.",
			map[string]any{"available": false},
		)
	}
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, fmt.Errorf("%w: invalid public MCP base URL", ErrStoreToolUnavailable)
	}
	origin := base.Scheme + "://" + base.Host
	ticket, err := t.personalKeys.CreateTicket(ctx, appoauth.PersonalKeyTicket{
		GatewayID:    rc.Consumer.GatewayID.String(),
		PrincipalSub: principal.Subject,
		MCPURL:       origin + appconsumer.MCPPath(consumerdomain.StoreSlug),
		LLMURL:       t.llmStoreURL(ctx, base.Scheme, gw),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: create personal key link: %w", ErrStoreToolUnavailable, err)
	}
	link := origin + appoauth.PersonalKeyPagePath + "?" + url.Values{"ticket": {ticket}}.Encode()
	text := "Present this link to the user so they can create their personal key: " + linkMarkdown("Personal key", link) +
		". They sign in there and the key is shown to them, once; it is never shown to you, so do not ask them to paste it here. " +
		"Let them decide whether to open it. Do not claim that it opened automatically."
	return marshalToolResult(text, map[string]any{
		"personal_key_url":   link,
		"personal_key_label": "Personal key",
		"action":             "user_confirmation_required",
	})
}

// llmStoreURL is where the key reaches the person's models: the LLM Store on
// the proxy plane, when the gateway has models a personal key can reach.
func (t *storeTool) llmStoreURL(ctx context.Context, scheme string, gw *gatewaydomain.Gateway) string {
	data, ok := appconsumer.DataFromContext(ctx)
	if !ok || data == nil || !data.HasPersonalConsumers() || gw == nil {
		return ""
	}
	host := strings.TrimSpace(gw.Domain)
	if host == "" {
		base := strings.Trim(strings.TrimSpace(t.proxyDomain), ".")
		if base == "" || gw.Slug == "" {
			return ""
		}
		host = gw.Slug + "." + base
	}
	return scheme + "://" + host + "/" + consumerdomain.StoreSlug + "/v1"
}

func storePersonalKeyDefinition() (Tool, error) {
	raw, err := json.Marshal(map[string]any{
		"name":  StorePersonalKeyToolName,
		"title": "Get a personal key",
		"description": "Hand the user the page where they create their personal key for this gateway, or rotate or revoke the one they have. " +
			"The key lets them use their Store tools and their models from their own code or another client — the TrustGate SDK, any OpenAI-compatible SDK, or an MCP client — running as them, with what Access grants them. " +
			"Call this when the user asks for an API key or a personal key, or how to use their tools or models from code. " +
			"It returns a link for the user to open; the key is shown to them on that page, once, after they sign in — never to you." + GatewayToolDisclaimer,
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           map[string]any{},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    true,
			"destructiveHint": false,
			"idempotentHint":  false,
			"openWorldHint":   false,
		},
	})
	if err != nil {
		return Tool{}, err
	}
	var def Tool
	if err := json.Unmarshal(raw, &def); err != nil {
		return Tool{}, err
	}
	return def, nil
}
