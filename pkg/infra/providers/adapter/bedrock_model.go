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

package adapter

import "strings"

var bedrockInferenceProfilePrefixes = []string{
	"us-gov.", "us.", "eu.", "apac.", "jp.", "au.", "ca.", "global.",
}

// BedrockModelID returns the lowercased foundation-model ID a Bedrock model
// identifier runs, with one cross-region inference-profile prefix removed. A
// foundation-model or system inference-profile ARN resolves through the ID it
// ends with. Application inference profiles, provisioned throughput and
// custom models name no model in their ARN and return "".
func BedrockModelID(model string) string {
	id := strings.ToLower(strings.TrimSpace(model))
	if strings.HasPrefix(id, "arn:") {
		id = bedrockARNModelID(id)
	}
	for _, prefix := range bedrockInferenceProfilePrefixes {
		if rest, ok := strings.CutPrefix(id, prefix); ok {
			return rest
		}
	}
	return id
}

func bedrockARNModelID(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	kind, _, ok := strings.Cut(parts[5], "/")
	if !ok || (kind != "foundation-model" && kind != "inference-profile") {
		return ""
	}
	return parts[5][strings.LastIndex(parts[5], "/")+1:]
}

// BedrockModelVendor returns the provider part of a Bedrock model ID
// ("anthropic", "amazon", "meta", …), or "" when the identifier does not say
// which model it runs.
func BedrockModelVendor(model string) string {
	vendor, _, ok := strings.Cut(BedrockModelID(model), ".")
	if !ok {
		return ""
	}
	return vendor
}
