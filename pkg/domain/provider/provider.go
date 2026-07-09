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

// Package provider is the single source of truth for the LLM provider names
// the gateway can route to. Both the domain (registry validation) and the
// infra provider adapters depend on these identifiers.
package provider

const (
	OpenAI           = "openai"
	OpenAICompatible = "openai_compatible"
	Google           = "google"
	Vertex           = "vertex"
	Anthropic        = "anthropic"
	Bedrock          = "bedrock"
	Azure            = "azure"
	Mistral          = "mistral"
	Groq             = "groq"
	DeepSeek         = "deepseek"
	XAI              = "xai"
)

// Supported returns every provider name the gateway can route to.
func Supported() []string {
	return []string{
		OpenAI,
		OpenAICompatible,
		Google,
		Vertex,
		Anthropic,
		Bedrock,
		Azure,
		Mistral,
		Groq,
		DeepSeek,
		XAI,
	}
}

// IsValid reports whether name is a supported provider.
func IsValid(name string) bool {
	switch name {
	case OpenAI,
		OpenAICompatible,
		Google,
		Vertex,
		Anthropic,
		Bedrock,
		Azure,
		Mistral,
		Groq,
		DeepSeek,
		XAI:
		return true
	default:
		return false
	}
}
