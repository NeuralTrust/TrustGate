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

package catalog

import "github.com/NeuralTrust/AgentGateway/pkg/infra/providers"

type OptionFieldType string

const (
	OptionFieldTypeString OptionFieldType = "string"
	OptionFieldTypeEnum   OptionFieldType = "enum"
	OptionFieldTypeMap    OptionFieldType = "map"
)

type ProviderOptionField struct {
	Key         string          `json:"key"`
	Label       string          `json:"label"`
	Type        OptionFieldType `json:"type"`
	Description string          `json:"description,omitempty"`
	Required    bool            `json:"required,omitempty"`
	Default     any             `json:"default,omitempty"`
	Enum        []string        `json:"enum,omitempty"`
}

var providerOptionsCatalog = map[string][]ProviderOptionField{
	providers.ProviderOpenAI: {
		{
			Key:         "api",
			Label:       "API",
			Type:        OptionFieldTypeEnum,
			Description: "OpenAI API surface to target.",
			Enum:        []string{providers.OpenAIAPICompletions, providers.OpenAIAPIResponses},
		},
		{
			Key:         "base_url",
			Label:       "Base URL",
			Type:        OptionFieldTypeString,
			Description: "Optional override for the OpenAI base URL (http/https).",
		},
	},
	providers.ProviderOpenAICompatible: {
		{
			Key:         "base_url",
			Label:       "Base URL",
			Type:        OptionFieldTypeString,
			Description: "Base URL of the OpenAI-compatible endpoint (http/https).",
			Required:    true,
		},
		{
			Key:         "headers",
			Label:       "Headers",
			Type:        OptionFieldTypeMap,
			Description: "Extra HTTP headers sent with every upstream request.",
		},
	},
	providers.ProviderVertex: {
		{
			Key:         "project",
			Label:       "Project",
			Type:        OptionFieldTypeString,
			Description: "GCP project ID hosting the Vertex AI models.",
			Required:    true,
		},
		{
			Key:         "location",
			Label:       "Location",
			Type:        OptionFieldTypeString,
			Description: "GCP region of the Vertex AI endpoint (e.g. us-central1).",
			Required:    true,
		},
		{
			Key:         "version",
			Label:       "API Version",
			Type:        OptionFieldTypeString,
			Description: "Vertex AI API version.",
			Default:     "v1",
		},
	},
}

func ProviderOptions(code string) []ProviderOptionField {
	if opts, ok := providerOptionsCatalog[code]; ok {
		return opts
	}
	return []ProviderOptionField{}
}
