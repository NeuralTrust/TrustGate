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

package request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// GCPServiceAccountJSON stores a service-account key as a compact JSON string.
// UnmarshalJSON accepts either a JSON string or a JSON object so BodyParser does not 422 on nested keys.
type GCPServiceAccountJSON string

// UnmarshalJSON accepts a JSON string or object and normalizes object/pretty JSON to a compact string.
func (s *GCPServiceAccountJSON) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*s = ""
		return nil
	}

	switch data[0] {
	case '"':
		var raw string
		if err := json.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("gcp_service_account: %w", err)
		}
		*s = GCPServiceAccountJSON(compactServiceAccountJSON(raw))
		return nil
	case '{':
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			return fmt.Errorf("gcp_service_account: %w", err)
		}
		compact, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("gcp_service_account: %w", err)
		}
		*s = GCPServiceAccountJSON(compact)
		return nil
	default:
		return fmt.Errorf("gcp_service_account must be a JSON string or object")
	}
}

func (s *GCPServiceAccountJSON) stringPtr() *string {
	if s == nil {
		return nil
	}
	v := string(*s)
	return &v
}

func compactServiceAccountJSON(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return trimmed
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return raw
	}
	compact, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return string(compact)
}

func projectIDFromServiceAccount(sa string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(sa)), &obj); err != nil {
		return ""
	}
	id, _ := obj["project_id"].(string)
	return strings.TrimSpace(id)
}

func authServiceAccountString(auth *TargetAuthRequest) string {
	if auth == nil || auth.GCPServiceAccount == nil {
		return ""
	}
	return strings.TrimSpace(string(*auth.GCPServiceAccount))
}

func providerOptionString(options map[string]any, key string) string {
	if options == nil {
		return ""
	}
	raw, ok := options[key]
	if !ok || raw == nil {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func shouldInferVertexProject(provider string, auth *TargetAuthRequest) bool {
	if strings.EqualFold(strings.TrimSpace(provider), providers.ProviderVertex) {
		return true
	}
	return auth != nil && strings.EqualFold(strings.TrimSpace(auth.Type), string(domain.AuthTypeGCPServiceAccount))
}

func inferVertexProject(provider string, options map[string]any, auth *TargetAuthRequest) map[string]any {
	if !shouldInferVertexProject(provider, auth) {
		return options
	}
	if providerOptionString(options, "project") != "" {
		return options
	}
	projectID := projectIDFromServiceAccount(authServiceAccountString(auth))
	if projectID == "" {
		return options
	}
	if options == nil {
		options = map[string]any{}
	}
	options["project"] = projectID
	return options
}
