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

package response

import (
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type ProviderResponse struct {
	ID                    ids.ProviderID                   `json:"id"`
	Code                  string                           `json:"code"`
	DisplayName           string                           `json:"display_name"`
	WireFormat            string                           `json:"wire_format"`
	Source                string                           `json:"source"`
	Metadata              map[string]any                   `json:"metadata,omitempty"`
	AuthTypes             []appcatalog.AuthTypeOption      `json:"auth_types"`
	ProviderOptionsSchema []appcatalog.ProviderOptionField `json:"provider_options_schema"`
}

type ModelResponse struct {
	ID            ids.ModelID    `json:"id"`
	ProviderID    ids.ProviderID `json:"provider_id"`
	Slug          string         `json:"slug"`
	ExternalID    string         `json:"external_id,omitempty"`
	DisplayName   string         `json:"display_name,omitempty"`
	ContextWindow int            `json:"context_window,omitempty"`
	MaxOutput     int            `json:"max_output,omitempty"`
	InputPrice    string         `json:"input_price,omitempty"`
	OutputPrice   string         `json:"output_price,omitempty"`
	Capabilities  map[string]any `json:"capabilities,omitempty"`
	Enabled       bool           `json:"enabled"`
	Source        string         `json:"source"`
}

func FromProvider(p domain.Provider) ProviderResponse {
	return ProviderResponse{
		ID:          p.ID,
		Code:        p.Code,
		DisplayName: p.DisplayName,
		WireFormat:  p.WireFormat,
		Source:      p.Source,
		Metadata:    p.Metadata,
		AuthTypes:   appcatalog.ProviderAuthOptions(p.Code),

		ProviderOptionsSchema: appcatalog.ProviderOptions(p.Code),
	}
}

func FromModel(m domain.Model) ModelResponse {
	return ModelResponse{
		ID:            m.ID,
		ProviderID:    m.ProviderID,
		Slug:          m.Slug,
		ExternalID:    m.ExternalID,
		DisplayName:   m.DisplayName,
		ContextWindow: m.ContextWindow,
		MaxOutput:     m.MaxOutput,
		InputPrice:    m.InputPrice,
		OutputPrice:   m.OutputPrice,
		Capabilities:  m.Capabilities,
		Enabled:       m.Enabled,
		Source:        m.Source,
	}
}
