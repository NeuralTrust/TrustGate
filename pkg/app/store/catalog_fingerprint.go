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

package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// catalogFingerprintView is the catalog-derived shelf of an MCP target.
// Secrets, origin, headers, and per-user overlays are absent: two rows match
// only when an admin left every catalog field at the value the seed produced.
type catalogFingerprintView struct {
	URL       string              `json:"url"`
	Transport string              `json:"transport"`
	Auth      catalogAuthView     `json:"auth"`
	URLVars   []catalogURLVarView `json:"url_variables,omitempty"`
}

type catalogAuthView struct {
	Mode                    string   `json:"mode"`
	Header                  string   `json:"header,omitempty"`
	Provider                string   `json:"provider,omitempty"`
	Registration            string   `json:"registration,omitempty"`
	AuthorizeURL            string   `json:"authorize_url,omitempty"`
	TokenURL                string   `json:"token_url,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	Resource                string   `json:"resource,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

type catalogURLVarView struct {
	Name        string                    `json:"name"`
	Description string                    `json:"description,omitempty"`
	Required    bool                      `json:"required,omitempty"`
	Secret      bool                      `json:"secret,omitempty"`
	In          string                    `json:"in,omitempty"`
	Options     []catalogURLVarOptionView `json:"options,omitempty"`
	HostSuffix  []string                  `json:"host_suffix,omitempty"`
}

type catalogURLVarOptionView struct {
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

// catalogFingerprint is a stable hash of the catalog-derived fields. Nil and
// empty slices hash the same. Scope order is preserved.
func catalogFingerprint(target *registrydomain.MCPTarget) (string, error) {
	raw, err := json.Marshal(catalogFingerprintOf(target))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func catalogFingerprintOf(target *registrydomain.MCPTarget) catalogFingerprintView {
	view := catalogFingerprintView{
		Transport: string(registrydomain.MCPTransportStreamableHTTP),
		Auth:      catalogAuthView{Mode: string(registrydomain.MCPAuthModeNone)},
	}
	if target == nil {
		return view
	}
	view.URL = strings.TrimSpace(target.URL)
	if transport := strings.TrimSpace(string(target.Transport)); transport != "" {
		view.Transport = transport
	}
	if target.Auth != nil {
		mode := strings.TrimSpace(string(target.Auth.Mode))
		if mode == "" {
			mode = string(registrydomain.MCPAuthModeNone)
		}
		view.Auth = catalogAuthView{
			Mode:                    mode,
			Header:                  strings.TrimSpace(target.Auth.Header),
			Provider:                strings.TrimSpace(target.Auth.Provider),
			Registration:            strings.TrimSpace(string(target.Auth.Registration)),
			AuthorizeURL:            strings.TrimSpace(target.Auth.AuthorizeURL),
			TokenURL:                strings.TrimSpace(target.Auth.TokenURL),
			Scopes:                  nilIfEmpty(target.Auth.Scopes),
			Resource:                strings.TrimSpace(target.Auth.Resource),
			TokenEndpointAuthMethod: strings.TrimSpace(target.Auth.TokenEndpointAuthMethod),
		}
	}
	if len(target.URLVariables) == 0 {
		return view
	}
	view.URLVars = make([]catalogURLVarView, 0, len(target.URLVariables))
	for _, variable := range target.URLVariables {
		item := catalogURLVarView{
			Name:        strings.TrimSpace(variable.Name),
			Description: strings.TrimSpace(variable.Description),
			Required:    variable.Required,
			Secret:      variable.Secret,
			In:          strings.TrimSpace(variable.In),
			HostSuffix:  nilIfEmpty(variable.HostSuffix),
		}
		if len(variable.Options) > 0 {
			item.Options = make([]catalogURLVarOptionView, 0, len(variable.Options))
			for _, option := range variable.Options {
				item.Options = append(item.Options, catalogURLVarOptionView{
					Value: strings.TrimSpace(option.Value),
					Label: strings.TrimSpace(option.Label),
				})
			}
		}
		view.URLVars = append(view.URLVars, item)
	}
	return view
}

func nilIfEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = strings.TrimSpace(value)
	}
	return out
}
