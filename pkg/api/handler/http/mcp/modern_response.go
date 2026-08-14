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
	"bytes"
	"encoding/json"
	"errors"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const (
	modernCacheTTLDefault = 300000
	modernCacheTTLRead    = 0
	modernServerInfoKey   = "io.modelcontextprotocol/serverInfo"
)

var errModernResultNotObject = errors.New("modern MCP result must be an object")

func normalizeModernResult(
	method string,
	result any,
	rc *appconsumer.RoutableConsumer,
	caps map[string]any,
) (map[string]any, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	var normalized map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&normalized); err != nil || normalized == nil {
		return nil, errModernResultNotObject
	}

	if method == "tools/list" {
		removeMCPHeaderAnnotations(normalized)
	}

	metadata := make(map[string]any)
	if existing, ok := normalized["_meta"]; ok {
		existingMetadata, ok := existing.(map[string]any)
		if !ok {
			return nil, errModernResultNotObject
		}
		metadata = existingMetadata
	}
	metadata[modernServerInfoKey] = map[string]any{
		"name":    serverName,
		"version": serverVersion + "+" + surfaceFingerprint(rc),
	}
	normalized["_meta"] = metadata
	applyMRTRFields(method, normalized, caps)
	delete(normalized, "ttlMs")
	delete(normalized, "cacheScope")

	switch method {
	case "server/discover", "tools/list", "resources/list", "resources/templates/list", "prompts/list":
		normalized["ttlMs"] = modernCacheTTLDefault
		normalized["cacheScope"] = "private"
	case "resources/read":
		normalized["ttlMs"] = modernCacheTTLRead
		normalized["cacheScope"] = "private"
	}

	return normalized, nil
}

// applyMRTRFields keeps continuation state on tools/call and nowhere else: the
// mediation contract is tools-first, so every other method reports complete and
// loses any upstream MRTR fields.
func applyMRTRFields(method string, normalized map[string]any, caps map[string]any) {
	if method != "tools/call" || normalized["resultType"] != trace.MRTROutcomeInputRequired {
		normalized["resultType"] = trace.MRTROutcomeComplete
		delete(normalized, "requestState")
		delete(normalized, "inputRequests")
		return
	}
	normalized["resultType"] = trace.MRTROutcomeInputRequired
	requests, ok := normalized["inputRequests"].(map[string]any)
	if !ok {
		return
	}
	normalized["inputRequests"] = declaredInputRequests(requests, caps)
}

// declaredInputRequests drops kinds the client never declared: forwarding them
// would ask for input the client cannot supply.
func declaredInputRequests(requests map[string]any, caps map[string]any) map[string]any {
	allowed := make(map[string]any, len(requests))
	for id, request := range requests {
		entry, ok := request.(map[string]any)
		if !ok {
			continue
		}
		method, _ := entry["method"].(string)
		kind := appmcp.InputRequestKind(method)
		if kind == "" || !appmcp.DeclaredCapability(caps, kind) {
			continue
		}
		allowed[id] = request
	}
	return allowed
}

func removeMCPHeaderAnnotations(value any) {
	switch current := value.(type) {
	case map[string]any:
		delete(current, "x-mcp-header")
		for _, nested := range current {
			removeMCPHeaderAnnotations(nested)
		}
	case []any:
		for _, nested := range current {
			removeMCPHeaderAnnotations(nested)
		}
	}
}
