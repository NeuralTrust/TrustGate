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
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// StoreModelsToolName lists the LLM providers and models the user reaches
// with their personal key.
const StoreModelsToolName = StoreToolNamePrefix + "models"

// OwnedKeyFinder finds the personal key a user holds on a gateway.
// authdomain.Repository satisfies it.
type OwnedKeyFinder interface {
	FindByOwner(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*authdomain.Auth, error)
}

// StoreModel is one model a personal key reaches, and the provider serving it.
type StoreModel struct {
	ID       string
	Provider string
}

// StoreModelLister lists the models a key's personal consumers serve, exactly
// as the key's own /store/v1/models answers. The container adapts the proxy's
// StoreModels to it.
type StoreModelLister interface {
	StoreModels(ctx context.Context, links []appconsumer.StoreLink, data *appconsumer.Data) ([]StoreModel, error)
}

// WithStoreToolModels offers the models tool. proxyDomain is the LLM plane's
// base domain, for the URL the models are called at.
func WithStoreToolModels(keys OwnedKeyFinder, models StoreModelLister, proxyDomain string) StoreToolOption {
	return func(t *storeTool) {
		t.ownedKeys = keys
		t.modelLister = models
		if t.proxyDomain == "" {
			t.proxyDomain = proxyDomain
		}
	}
}

type storeModelsProvider struct {
	Provider string   `json:"provider"`
	Models   []string `json:"models"`
}

// models answers the tool with what the caller's personal key reaches: the
// same list its /store/v1/models gives, grouped by provider, and where to call
// them. The key itself is never part of the answer.
func (t *storeTool) models(ctx context.Context, baseURL string) (json.RawMessage, error) {
	if t.ownedKeys == nil || t.modelLister == nil {
		return nil, fmt.Errorf("%w: models are not available here", ErrStoreToolUnavailable)
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return nil, ErrNoPrincipal
	}
	gw, _ := appgateway.FromContext(ctx)
	if gw == nil {
		return nil, fmt.Errorf("%w: no gateway on this request", ErrStoreToolUnavailable)
	}
	if !gw.AllowsPersonal() {
		return marshalToolResult(
			"Models through a personal key are not available on this gateway: it runs on the organisation's own infrastructure.",
			map[string]any{"available": false, "providers": []storeModelsProvider{}},
		)
	}
	key, err := t.ownedKeys.FindByOwner(ctx, gw.ID, principal.Subject)
	switch {
	case errors.Is(err, authdomain.ErrNotFound):
		return marshalToolResult(
			"The user has no personal key on this gateway yet, and their models are called with it. Offer "+StorePersonalKeyToolName+" to get one; then call this again.",
			map[string]any{"available": true, "has_key": false, "providers": []storeModelsProvider{}},
		)
	case err != nil:
		return nil, fmt.Errorf("%w: find personal key: %w", ErrStoreToolUnavailable, err)
	}
	if !key.IsPersonalKey(time.Now().UTC()) {
		return marshalToolResult(
			"The user's personal key has expired or is disabled, so it reaches no models. Offer "+StorePersonalKeyToolName+" to renew it.",
			map[string]any{"available": true, "has_key": true, "key_active": false, "providers": []storeModelsProvider{}},
		)
	}
	data, _ := appconsumer.DataFromContext(ctx)
	links := data.StoreLinks(key.ID)
	listed, err := t.modelLister.StoreModels(ctx, links, data)
	if err != nil {
		return nil, fmt.Errorf("%w: list models: %w", ErrStoreToolUnavailable, err)
	}
	providers := groupStoreModels(listed)
	structured := map[string]any{"available": true, "has_key": true, "key_active": true, "providers": providers}
	if len(providers) == 0 {
		return marshalToolResult(
			"The user's personal key reaches no models yet. An administrator gives access in Access, or the user requests a provider's models "+t.requestModelsHow()+".",
			structured,
		)
	}
	baseURLOut := ""
	if base, err := url.Parse(strings.TrimSpace(baseURL)); err == nil && (base.Scheme == "http" || base.Scheme == "https") {
		baseURLOut = t.llmStoreURL(ctx, base.Scheme, gw)
	}
	var b strings.Builder
	count := 0
	for _, p := range providers {
		count += len(p.Models)
	}
	fmt.Fprintf(&b, "With their personal key the user can call %d models", count)
	if baseURLOut != "" {
		structured["base_url"] = baseURLOut
		fmt.Fprintf(&b, " at %s (OpenAI-compatible; pass the model id as `model`)", baseURLOut)
	}
	b.WriteString(":")
	for _, p := range providers {
		fmt.Fprintf(&b, "\n- %s: %s", p.Provider, strings.Join(p.Models, ", "))
	}
	fmt.Fprintf(&b, "\nFor a provider not listed here, the user can ask for its models %s.", t.requestModelsHow())
	return marshalToolResult(b.String(), structured)
}

// requestModelsHow says where a user asks for a provider's models: the request
// tool when the Store offers it, the Portal otherwise.
func (t *storeTool) requestModelsHow() string {
	if t.modelRequests != nil && t.modelRequestLinks != nil {
		return "with " + StoreRequestModelsToolName
	}
	return "from the Portal"
}

// groupStoreModels groups models by provider, providers and models sorted.
func groupStoreModels(models []StoreModel) []storeModelsProvider {
	byProvider := map[string][]string{}
	for _, m := range models {
		id := strings.TrimSpace(m.ID)
		if id == "" {
			continue
		}
		provider := strings.TrimSpace(m.Provider)
		if !slices.Contains(byProvider[provider], id) {
			byProvider[provider] = append(byProvider[provider], id)
		}
	}
	out := make([]storeModelsProvider, 0, len(byProvider))
	for provider, ids := range byProvider {
		slices.Sort(ids)
		out = append(out, storeModelsProvider{Provider: provider, Models: ids})
	}
	slices.SortFunc(out, func(a, b storeModelsProvider) int { return strings.Compare(a.Provider, b.Provider) })
	return out
}

func storeModelsDefinition() (Tool, error) {
	raw, err := json.Marshal(map[string]any{
		"name":  StoreModelsToolName,
		"title": "List my models",
		"description": "List the LLM providers and models the user can call with their personal key through this gateway, and the OpenAI-compatible base URL to call them at. " +
			"Call this when the user asks which models or providers they have, or which model id to use in their code. " +
			"If they have no personal key yet, it says so, and " + StorePersonalKeyToolName + " gets them one. The key itself is never returned." + GatewayToolDisclaimer,
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           map[string]any{},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    true,
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
