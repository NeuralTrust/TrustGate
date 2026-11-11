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

package a2a

import (
	"bytes"
	"encoding/json"
	"errors"
)

const (
	apiKeyHeader     = "X-AG-API-Key" // #nosec G101 -- HTTP header name, not a credential
	apiKeySchemeName = "gateway_api_key"
	bindingJSONRPC   = "JSONRPC"
)

// RenderCard is the pinned card as the gateway serves it: endpoint as the
// only JSON-RPC interface, the gateway API key as the only security scheme,
// push notifications and the extended card off, no signatures and no skill
// security. Unknown fields are kept. a2a-sdk 1.x serves both versions'
// fields in one card; the other version's interface and security fields are
// removed so they cannot point at the agent. jsonrpcOnly leaves
// additionalInterfaces out of a 0.3 card, for an agent whose own card
// advertises HTTP+JSON (Vertex).
func RenderCard(card []byte, v Version, endpoint string, jsonrpcOnly bool) ([]byte, error) {
	c, ok := decodeMap(card)
	if !ok {
		return nil, errors.New("a2a: the pinned card is not a JSON object")
	}
	caps, _ := c["capabilities"].(map[string]any)
	if caps == nil {
		caps = map[string]any{}
	}
	caps["pushNotifications"] = false
	c["capabilities"] = caps
	delete(c, "signatures")
	if skills, ok := c["skills"].([]any); ok {
		for _, s := range skills {
			if skill, ok := s.(map[string]any); ok {
				delete(skill, "security")
				delete(skill, "securityRequirements")
			}
		}
	}
	if v == Version03 {
		render03(c, caps, endpoint, jsonrpcOnly)
	} else {
		render10(c, caps, endpoint)
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

func render03(c, caps map[string]any, endpoint string, jsonrpcOnly bool) {
	c["url"] = endpoint
	c["preferredTransport"] = bindingJSONRPC
	if jsonrpcOnly {
		delete(c, "additionalInterfaces")
	} else {
		c["additionalInterfaces"] = []any{map[string]any{"url": endpoint, "transport": bindingJSONRPC}}
	}
	c["securitySchemes"] = map[string]any{apiKeySchemeName: map[string]any{"type": "apiKey", "in": "header", "name": apiKeyHeader}}
	c["security"] = []any{map[string]any{apiKeySchemeName: []any{}}}
	c["supportsAuthenticatedExtendedCard"] = false
	delete(c, "supportedInterfaces")
	delete(c, "securityRequirements")
	delete(caps, "extendedAgentCard")
}

func render10(c, caps map[string]any, endpoint string) {
	c["supportedInterfaces"] = []any{map[string]any{"url": endpoint, "protocolBinding": bindingJSONRPC, "protocolVersion": string(Version10)}}
	c["securitySchemes"] = map[string]any{apiKeySchemeName: map[string]any{"apiKeySecurityScheme": map[string]any{"location": "header", "name": apiKeyHeader}}}
	c["securityRequirements"] = []any{map[string]any{"schemes": map[string]any{apiKeySchemeName: map[string]any{"list": []any{}}}}}
	caps["extendedAgentCard"] = false
	for _, k := range []string{"url", "preferredTransport", "additionalInterfaces", "security", "supportsAuthenticatedExtendedCard", "protocolVersion"} {
		delete(c, k)
	}
}

// Streaming reports whether a card declares capabilities.streaming true.
func Streaming(card []byte) bool {
	var c struct {
		Capabilities struct {
			Streaming bool `json:"streaming"`
		} `json:"capabilities"`
	}
	return json.Unmarshal(card, &c) == nil && c.Capabilities.Streaming
}
