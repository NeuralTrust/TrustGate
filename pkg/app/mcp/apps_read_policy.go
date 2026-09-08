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
	"encoding/json"
	"strings"
)

// AppsReadResult marks a validated Apps resource result for raw transport.
type AppsReadResult json.RawMessage

// AppsReadPolicy validates MCP Apps resource reads without rewriting results.
type AppsReadPolicy struct {
	enabled  bool
	maxBytes int
	metadata AppsMetadataPolicy
}

// NewAppsReadPolicy builds an immutable Apps read policy.
func NewAppsReadPolicy(enabled bool, maxBytes int, metadata AppsMetadataPolicy) AppsReadPolicy {
	return AppsReadPolicy{enabled: enabled, maxBytes: maxBytes, metadata: metadata}
}

// RequiresValidation reports whether a URI is governed by the Apps read policy.
func (p AppsReadPolicy) RequiresValidation(uri string) bool {
	return p.enabled && strings.HasPrefix(uri, "ui://")
}

// ValidateReadRequest validates an Apps URI and client capability.
func (p AppsReadPolicy) ValidateReadRequest(uri string, capability MCPAppsClientCapability) error {
	if _, err := ValidateAppsURI(uri); err != nil {
		return ErrAppsResourceRejected
	}
	if !supportsMCPApps(capability) {
		return ErrAppsResourceRejected
	}
	return nil
}

// ValidateReadResult validates an Apps document and returns its original bytes.
func (p AppsReadPolicy) ValidateReadResult(uri string, raw json.RawMessage) (json.RawMessage, error) {
	if _, err := ValidateAppsDocument(uri, p.maxBytes, raw); err != nil {
		return nil, err
	}
	var result struct {
		Meta     map[string]any `json:"_meta"`
		Contents []struct {
			Meta map[string]any `json:"_meta"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Contents) != 1 {
		return nil, ErrAppsResourceRejected
	}
	if metadata, present := SelectResourceAppsMetadata(result.Meta, result.Contents[0].Meta); present {
		if err := ValidateResourceAppsMetadata(metadata, p.metadata); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// ValidateCallResult validates a classified or self-marked Apps tool result.
func (p AppsReadPolicy) ValidateCallResult(raw json.RawMessage, classified ...bool) (json.RawMessage, error) {
	if !p.enabled {
		return raw, nil
	}
	appsCall := len(classified) > 0 && classified[0]
	if appsCall && (len(raw) == 0 || len(raw) > p.maxBytes) {
		return nil, ErrAppsResourceRejected
	}
	if !appsCall {
		var envelope struct {
			Meta json.RawMessage `json:"_meta"`
		}
		if json.Unmarshal(raw, &envelope) != nil {
			return raw, nil
		}
		meta, marked := markedAppsMetadata(envelope.Meta, appsMetadataMarker)
		if !marked {
			return raw, nil
		}
		if meta == nil {
			return nil, ErrAppsResourceRejected
		}
		if _, err := ParseToolAppsMetadata(meta); err != nil {
			return nil, ErrAppsResourceRejected
		}
	}
	var result struct {
		Content []struct {
			Type string `json:"type"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		Meta              json.RawMessage `json:"_meta"`
		IsError           json.RawMessage `json:"isError"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return nil, ErrAppsResourceRejected
	}
	if len(raw) == 0 || len(raw) > p.maxBytes || validateAppsJSON(raw) != nil || result.Content == nil {
		return nil, ErrAppsResourceRejected
	}
	for _, block := range result.Content {
		if block.Type == "" {
			return nil, ErrAppsResourceRejected
		}
	}
	for _, value := range []json.RawMessage{result.StructuredContent, result.Meta} {
		if len(value) > 0 {
			var object map[string]json.RawMessage
			if json.Unmarshal(value, &object) != nil || object == nil {
				return nil, ErrAppsResourceRejected
			}
		}
	}
	if len(result.IsError) > 0 {
		var isError bool
		if json.Unmarshal(result.IsError, &isError) != nil {
			return nil, ErrAppsResourceRejected
		}
	}
	return raw, nil
}
