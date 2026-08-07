package mcp

import (
	"bytes"
	"encoding/json"
	"errors"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
)

const (
	modernCacheTTLDefault = 300000
	modernCacheTTLRead    = 0
	modernServerInfoKey   = "io.modelcontextprotocol/serverInfo"
)

var errModernResultNotObject = errors.New("modern MCP result must be an object")

func normalizeModernResult(method string, result any, rc *appconsumer.RoutableConsumer) (map[string]any, error) {
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
	normalized["resultType"] = "complete"
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
