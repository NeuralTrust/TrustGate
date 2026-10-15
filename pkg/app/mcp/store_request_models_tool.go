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

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

// StoreRequestModelsToolName asks an administrator for a provider's models,
// as the install tool asks for an MCP server outside the user's access.
const StoreRequestModelsToolName = StoreToolNamePrefix + "request_models"

// ModelRequestLinks mints the ticket a model request page link carries.
// appoauth.ModelRequestPages satisfies it.
type ModelRequestLinks interface {
	CreateTicket(ctx context.Context, t appoauth.ModelRequestTicket) (string, error)
}

// WithStoreToolModelRequests offers the request tool: console checks a
// request when it is asked for, and links mints the form the person files it
// from.
func WithStoreToolModelRequests(console appoauth.ModelAccessConsole, links ModelRequestLinks) StoreToolOption {
	return func(t *storeTool) {
		t.modelRequests = console
		t.modelRequestLinks = links
	}
}

type storeRequestModelsArgs struct {
	Provider   string `json:"provider"`
	RegistryID string `json:"registry_id,omitempty"`
}

// requestModels answers the tool. What the user named is checked with the
// console first, so a provider they already reach, already asked for or the
// gateway cannot offer is said before anyone writes a reason. Otherwise the
// answer is the form where the person writes it: the tool takes no reason,
// since an agent asked for one writes it from its own task and an approver
// would read it as the person's.
func (t *storeTool) requestModels(ctx context.Context, baseURL string, arguments json.RawMessage) (json.RawMessage, error) {
	if t.modelRequests == nil || t.modelRequestLinks == nil {
		return nil, fmt.Errorf("%w: model requests are not available here", ErrStoreToolUnavailable)
	}
	var args storeRequestModelsArgs
	if len(arguments) > 0 {
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, fmt.Errorf("%w: invalid arguments: %w", ErrStoreToolUnavailable, err)
		}
	}
	args.Provider = strings.TrimSpace(args.Provider)
	args.RegistryID = strings.TrimSpace(args.RegistryID)
	if args.Provider == "" && args.RegistryID == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrStoreToolUnavailable)
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return nil, ErrNoPrincipal
	}
	gw, _ := appgateway.FromContext(ctx)
	if gw == nil {
		return nil, fmt.Errorf("%w: no gateway on this request", ErrStoreToolUnavailable)
	}
	if !gw.AllowsPersonal() || strings.TrimSpace(gw.TenantID()) == "" {
		return marshalToolResult(
			"Models through a personal key are not available on this gateway, so there is nothing to request here.",
			map[string]any{"available": false},
		)
	}
	query := appoauth.ModelAccessQuery{
		TeamID:     gw.TenantID(),
		GatewayID:  gw.ID.String(),
		UserID:     principal.Subject,
		Provider:   args.Provider,
		RegistryID: args.RegistryID,
	}
	answer, err := t.modelRequests.Check(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%w: check the request: %w", ErrStoreToolUnavailable, err)
	}
	switch answer.Status {
	case appoauth.ModelAccessOK:
		return t.modelRequestForm(ctx, baseURL, query, answer)
	case appoauth.ModelAccessChooseRegistry:
		return modelRequestChoice(answer)
	case appoauth.ModelAccessHasAccess:
		return marshalToolResult(
			answerError(answer, "The user already has access to these models.")+" "+StoreModelsToolName+" lists them.",
			map[string]any{"has_access": true, "name": answer.Name},
		)
	case appoauth.ModelAccessAlreadyAsked:
		return marshalToolResult(
			answerError(answer, "A request for these models is already waiting for an administrator.")+" Nothing more to do until they decide.",
			map[string]any{"already_requested": true, "name": answer.Name},
		)
	case appoauth.ModelAccessUnknown:
		return modelRequestUnknown(args.Provider, answer)
	default:
		return marshalToolResult(
			answerError(answer, "These models cannot be requested on this gateway."),
			map[string]any{"available": false},
		)
	}
}

// modelRequestForm hands back the form the person files the request from.
func (t *storeTool) modelRequestForm(ctx context.Context, baseURL string, q appoauth.ModelAccessQuery, answer *appoauth.ModelAccessAnswer) (json.RawMessage, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, fmt.Errorf("%w: invalid public MCP base URL", ErrStoreToolUnavailable)
	}
	name := strings.TrimSpace(answer.Name)
	if name == "" {
		name = q.Provider
	}
	ticket, err := t.modelRequestLinks.CreateTicket(ctx, appoauth.ModelRequestTicket{
		TeamID:       q.TeamID,
		GatewayID:    q.GatewayID,
		PrincipalSub: q.UserID,
		Provider:     answer.Provider,
		RegistryID:   answer.RegistryID,
		Name:         name,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: create model request link: %w", ErrStoreToolUnavailable, err)
	}
	link := base.Scheme + "://" + base.Host + appoauth.ModelRequestPagePath + "?" + url.Values{"ticket": {ticket}}.Encode()
	// The label is spelled out because a ticket URL is long: pasted raw it
	// buries the one thing the user has to do.
	label := "Request access to " + name + " models"
	return marshalToolResult(
		name+" models are outside the user's access, so getting them files a request an administrator has to decide on. "+
			"Show the user this as a link titled \""+label+"\", not as a bare URL: "+link+
			" — they write, in their own words, why they need them, and the request is filed when they submit the form. "+
			"Do not write the reason for them, and do not call this again for the same models.",
		map[string]any{
			"provider":           answer.Provider,
			"name":               name,
			"requires_reason":    true,
			"request_url":        link,
			"request_link_label": label,
		},
	)
}

func modelRequestChoice(answer *appoauth.ModelAccessAnswer) (json.RawMessage, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s has several registries on this gateway the user does not reach. Ask the user which one they need, then call %s again with its registry_id:", answer.Name, StoreRequestModelsToolName)
	choices := make([]map[string]string, 0, len(answer.Registries))
	for _, r := range answer.Registries {
		fmt.Fprintf(&b, "\n• %s — registry_id \"%s\"", r.Name, r.RegistryID)
		choices = append(choices, map[string]string{"registry_id": r.RegistryID, "name": r.Name})
	}
	return marshalToolResult(b.String(), map[string]any{
		"provider":                 answer.Provider,
		"name":                     answer.Name,
		"requires_registry_choice": true,
		"registries":               choices,
	})
}

func modelRequestUnknown(asked string, answer *appoauth.ModelAccessAnswer) (json.RawMessage, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "%q is not a provider this gateway knows.", asked)
	providers := make([]map[string]string, 0, len(answer.Providers))
	names := make([]string, 0, len(answer.Providers))
	for _, p := range answer.Providers {
		providers = append(providers, map[string]string{"provider": p.Provider, "name": p.Name})
		names = append(names, fmt.Sprintf("%s (%s)", p.Name, p.Provider))
	}
	if len(names) > 0 {
		fmt.Fprintf(&b, " Its providers are: %s. A provider an administrator can connect may be asked for by its name too.", strings.Join(names, ", "))
	}
	return marshalToolResult(b.String(), map[string]any{"unknown_provider": true, "providers": providers})
}

func answerError(answer *appoauth.ModelAccessAnswer, fallback string) string {
	if msg := strings.TrimSpace(answer.Error); msg != "" {
		if !strings.HasSuffix(msg, ".") {
			msg += "."
		}
		return msg
	}
	return fallback
}

func storeRequestModelsDefinition() (Tool, error) {
	raw, err := json.Marshal(map[string]any{
		"name":  StoreRequestModelsToolName,
		"title": "Request models",
		"description": "Ask an administrator for access to an LLM provider's models the user does not have yet, so they can call them with their personal key. " +
			"Call this when the user needs a provider or model that " + StoreModelsToolName + " does not list. " +
			"Name the provider (\"openai\", \"Anthropic\", \"Mistral\"); access is granted per provider, so for a model, name the provider that serves it. " +
			"It returns a link for the user: they write there, in their own words, why they need it, and the request is filed when they send it. " +
			"Never write the reason for them. If the provider has several registries, it lists them; ask the user which one and call again with its registry_id." + GatewayToolDisclaimer,
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider": map[string]any{
					"type":        "string",
					"description": "The provider whose models the user needs, by its name or code.",
				},
				"registry_id": map[string]any{
					"type":        "string",
					"description": "One registry of the provider, from a previous answer that listed several.",
				},
			},
			"required":             []string{"provider"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    false,
			"destructiveHint": false,
			"idempotentHint":  true,
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
