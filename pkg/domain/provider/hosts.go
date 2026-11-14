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

package provider

import "sort"

// WatsonxIAMHost is the IBM Cloud IAM host a watsonx registry sends its API
// key to, in exchange for the bearer token its inference calls carry.
const WatsonxIAMHost = "iam.cloud.ibm.com"

// defaultHosts is the API host each provider with a fixed endpoint calls
// when no base_url overrides it. Vertex, Bedrock, Azure and watsonx derive
// theirs from a location, region or endpoint; openai_compatible always names
// its own.
var defaultHosts = map[string]string{
	OpenAI:       "api.openai.com",
	Google:       "generativelanguage.googleapis.com",
	Anthropic:    "api.anthropic.com",
	Mistral:      "api.mistral.ai",
	Groq:         "api.groq.com",
	DeepSeek:     "api.deepseek.com",
	XAI:          "api.x.ai",
	Cerebras:     "api.cerebras.ai",
	OpenRouter:   "openrouter.ai",
	Cohere:       "api.cohere.com",
	Moonshot:     "api.moonshot.ai",
	DigitalOcean: "inference.do-ai.run",
}

// baseURLProviders read provider_options.base_url; every other provider
// ignores it and calls its own or its configured endpoint.
var baseURLProviders = map[string]bool{
	OpenAI: true, OpenAICompatible: true, Vertex: true, Cohere: true,
	Mistral: true, Anthropic: true, Groq: true, OpenRouter: true,
	Watsonx: true,
}

// watsonxRegions are the IBM Cloud regions that serve watsonx.ai. The region
// picks the host an IAM token is sent to, so no other value is accepted.
var watsonxRegions = map[string]bool{
	"us-south": true,
	"eu-de":    true,
	"eu-gb":    true,
	"jp-tok":   true,
	"au-syd":   true,
	"ca-tor":   true,
}

// WatsonxRegions returns the IBM Cloud regions that serve watsonx.ai, sorted.
func WatsonxRegions() []string {
	regions := make([]string, 0, len(watsonxRegions))
	for region := range watsonxRegions {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	return regions
}

// WatsonxHost is the watsonx.ai inference host of an IBM Cloud region, or ""
// for a region that does not serve watsonx.ai.
func WatsonxHost(region string) string {
	if !watsonxRegions[region] {
		return ""
	}
	return region + ".ml.cloud.ibm.com"
}

// HonorsBaseURL reports whether name calls provider_options.base_url when it
// is set.
func HonorsBaseURL(name string) bool {
	return baseURLProviders[name]
}

// DefaultHost returns the API host name calls when no base_url overrides it,
// or "" when its host is derived from its configuration.
func DefaultHost(name string) string {
	return defaultHosts[name]
}

// VertexHost is the Vertex AI host of a location: the global endpoint is the
// only one reached through an unprefixed host.
func VertexHost(location string) string {
	if location == "" {
		return ""
	}
	if location == "global" {
		return "aiplatform.googleapis.com"
	}
	return location + "-aiplatform.googleapis.com"
}
