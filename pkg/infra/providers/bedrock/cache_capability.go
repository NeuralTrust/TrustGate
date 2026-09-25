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

package bedrock

import "strings"

// cacheCapability is what a model accepts of Converse explicit caching:
// cachePoint at all, a 1h ttl, and a cachePoint in toolConfig.tools. Every
// listed model takes one in system and messages.
type cacheCapability struct {
	explicit bool
	ttl1h    bool
	tools    bool
}

var (
	claudeCache1h = cacheCapability{explicit: true, ttl1h: true, tools: true}
	claudeCache5m = cacheCapability{explicit: true, tools: true}
	novaCache     = cacheCapability{explicit: true}
)

// bedrockCacheFamilies takes the Claude entries, Fable and Mythos included,
// from the AWS "Supported models, Regions, and explicit caching limits" table
// (https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-caching.html)
// and the Nova entries, with their missing tools cachePoint and 1h ttl, from
// the Nova model cards; both read 2026-09-25.
// Minimum tokens per checkpoint (512 to 4,096 for Claude, 1K for Nova) are
// not enforced: a short prefix is still accepted, just not cached. GPT-5.6 on
// Bedrock caches through the Responses API only and is not a Converse entry.
var bedrockCacheFamilies = map[string]cacheCapability{
	"anthropic.claude-opus-5-5":               claudeCache1h,
	"anthropic.claude-opus-5":                 claudeCache1h,
	"anthropic.claude-fable-5-1":              claudeCache1h,
	"anthropic.claude-fable-5":                claudeCache1h,
	"anthropic.claude-mythos-5-1":             claudeCache1h,
	"anthropic.claude-mythos-5":               claudeCache1h,
	"anthropic.claude-sonnet-5":               claudeCache1h,
	"anthropic.claude-opus-4-8":               claudeCache1h,
	"anthropic.claude-opus-4-7":               claudeCache1h,
	"anthropic.claude-opus-4-6":               claudeCache1h,
	"anthropic.claude-opus-4-5":               claudeCache1h,
	"anthropic.claude-sonnet-4-6":             claudeCache1h,
	"anthropic.claude-sonnet-4-5":             claudeCache1h,
	"anthropic.claude-haiku-4-5":              claudeCache1h,
	"anthropic.claude-3-7-sonnet":             claudeCache5m,
	"anthropic.claude-3-5-sonnet-20241022-v2": claudeCache5m,
	"amazon.nova-micro":                       novaCache,
	"amazon.nova-lite":                        novaCache,
	"amazon.nova-pro":                         novaCache,
	"amazon.nova-premier":                     novaCache,
	"amazon.nova-2-lite":                      novaCache,
}

var inferenceProfilePrefixes = []string{
	"us-gov.", "us.", "eu.", "apac.", "jp.", "au.", "ca.", "global.",
}

// cacheCapabilityFor resolves a model ID to the longest listed family prefix
// that ends on an ID boundary, after one inference-profile prefix is
// stripped. A foundation-model or system inference-profile ARN resolves
// through the ID it ends with; any other ARN hides the model and, like an
// unlisted ID, gets no cachePoint.
func cacheCapabilityFor(model string) cacheCapability {
	id := strings.ToLower(strings.TrimSpace(model))
	if strings.HasPrefix(id, "arn:") {
		id = arnModelID(id)
	}
	if id == "" {
		return cacheCapability{}
	}
	for _, prefix := range inferenceProfilePrefixes {
		if rest, ok := strings.CutPrefix(id, prefix); ok {
			id = rest
			break
		}
	}
	var (
		best    cacheCapability
		bestLen int
	)
	for family, capability := range bedrockCacheFamilies {
		if len(family) > bestLen && familyMatches(id, family) {
			best, bestLen = capability, len(family)
		}
	}
	return best
}

// arnModelID returns the model or system inference-profile ID a Bedrock ARN
// names, and "" for application inference profiles, provisioned throughput
// and custom models, whose ARN does not say which model they run.
func arnModelID(arn string) string {
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

func familyMatches(id, family string) bool {
	rest, ok := strings.CutPrefix(id, family)
	if !ok {
		return false
	}
	return rest == "" || rest[0] == '-' || rest[0] == ':'
}
