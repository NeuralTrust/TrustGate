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
