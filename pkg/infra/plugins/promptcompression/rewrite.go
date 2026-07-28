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

package promptcompression

import "github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"

// rewriteRequest compresses the canonical request in place and re-encodes it.
// Because every transform is deterministic and applied uniformly to the whole
// conversation, a message compresses to the same bytes on every turn, so
// provider prompt-cache prefixes stay stable across requests.
func rewriteRequest(reg *adapter.Registry, format adapter.Format, creq *adapter.CanonicalRequest, cfg Settings) ([]byte, bool, int, error) {
	adp, err := reg.GetAdapter(format)
	if err != nil {
		return nil, false, 0, err
	}
	changed := false
	saved := 0
	if creq.System != "" && cfg.appliesToRole("system") {
		if out, did := compressContent(creq.System, cfg); did {
			saved += len(creq.System) - len(out)
			creq.System = out
			changed = true
		}
	}
	for i := range creq.Messages {
		msg := &creq.Messages[i]
		if !cfg.appliesToRole(msg.Role) {
			continue
		}
		if msg.Content != "" {
			if out, did := compressContent(msg.Content, cfg); did {
				saved += len(msg.Content) - len(out)
				msg.Content = out
				changed = true
			}
		}
		if cfg.CompressJSON {
			for j := range msg.ToolCalls {
				args := msg.ToolCalls[j].Arguments
				if args == "" || len(args) < cfg.MinLength {
					continue
				}
				if out := compactJSON(args); out != args {
					saved += len(args) - len(out)
					msg.ToolCalls[j].Arguments = out
					changed = true
				}
			}
		}
	}
	if !changed {
		return nil, false, 0, nil
	}
	body, err := adp.EncodeRequest(creq)
	if err != nil {
		return nil, false, 0, err
	}
	return body, true, saved, nil
}
