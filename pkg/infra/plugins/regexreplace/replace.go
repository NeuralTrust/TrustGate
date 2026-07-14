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

package regexreplace

import "github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"

func applyRules(rules []compiledRule, input string) (string, bool) {
	out := input
	for _, r := range rules {
		out = r.re.ReplaceAllString(out, r.replacement)
	}
	return out, out != input
}

func rewriteRequest(reg *adapter.Registry, format adapter.Format, creq *adapter.CanonicalRequest, rules []compiledRule) ([]byte, bool, error) {
	adp, err := reg.GetAdapter(format)
	if err != nil {
		return nil, false, err
	}
	changed := false
	if creq.System != "" {
		if out, did := applyRules(rules, creq.System); did {
			creq.System = out
			changed = true
		}
	}
	for i := range creq.Messages {
		if creq.Messages[i].Content == "" {
			continue
		}
		if out, did := applyRules(rules, creq.Messages[i].Content); did {
			creq.Messages[i].Content = out
			changed = true
		}
	}
	if !changed {
		return nil, false, nil
	}
	body, err := adp.EncodeRequest(creq)
	if err != nil {
		return nil, false, err
	}
	return body, true, nil
}

func rewriteResponse(reg *adapter.Registry, format adapter.Format, cresp *adapter.CanonicalResponse, rules []compiledRule) ([]byte, bool, error) {
	adp, err := reg.GetAdapter(format)
	if err != nil {
		return nil, false, err
	}
	out, changed := applyRules(rules, cresp.Content)
	if !changed {
		return nil, false, nil
	}
	cresp.Content = out
	body, err := adp.EncodeResponse(cresp)
	if err != nil {
		return nil, false, err
	}
	return body, true, nil
}
