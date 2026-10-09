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

package proxy

import (
	"regexp"
	"strings"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// anthropicBetaHeader is the header an Anthropic client opts into beta
// features with ("context-management-2025-06-27", …).
const anthropicBetaHeader = "anthropic-beta"

// maxAnthropicBetas bounds how many flags are carried upstream; a real client
// sends a handful.
const maxAnthropicBetas = 32

// anthropicBetaFlag is the shape of one flag: a short name of letters, digits,
// dots, dashes and underscores. Anything else is dropped rather than sent on.
var anthropicBetaFlag = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// anthropicBetas returns the caller's anthropic-beta flags, comma-joined, for
// an Anthropic-to-Anthropic passthrough, or "" when there are none.
//
// The body of such a request reaches Anthropic as the caller wrote it, beta
// fields included (Claude Code's context_management), and Anthropic refuses
// those fields ("Extra inputs are not permitted") unless the request opts into
// their beta. So the opt-in travels with the body. Every header line is read,
// as HTTP allows the list split across lines, and each flag is checked.
func anthropicBetas(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	var flags []string
	seen := make(map[string]struct{})
	for name, values := range req.Headers {
		if !strings.EqualFold(name, anthropicBetaHeader) {
			continue
		}
		for _, value := range values {
			for _, flag := range strings.Split(value, ",") {
				flag = strings.TrimSpace(flag)
				if !anthropicBetaFlag.MatchString(flag) {
					continue
				}
				if _, dup := seen[flag]; dup {
					continue
				}
				if len(flags) == maxAnthropicBetas {
					return strings.Join(flags, ",")
				}
				seen[flag] = struct{}{}
				flags = append(flags, flag)
			}
		}
	}
	return strings.Join(flags, ",")
}
