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

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func applyRules(rules []compiledRule, input string) (string, bool) {
	out := input
	for _, r := range rules {
		out = r.re.ReplaceAllString(out, r.replacement)
	}
	return out, out != input
}

// applyRulesFrom runs the rules over input the way applyRules does, except that
// a match lying wholly before from is left as it stands. It returns the
// rewritten text and the index of every rule that replaced something.
//
// A streamed block hands over the whole accumulated text, and everything before
// from has already been through these rules on an earlier block and been
// released with their masks in it. Matching it again only finds what those
// passes left behind: a placeholder that matches its own pattern ([SSN] under
// (?i)ssn), or a ^ or \b that now matches where a tail window happens to start.
// Rewriting either changes text the client already holds, which the guard
// refuses and turns into a cut (RUN-1745). A match that reaches from into the
// new text is still replaced, so a value split across two blocks is masked.
//
// When a rule replaces a match that starts before from, the text it touched is
// no longer what earlier passes saw, so from moves back to that match and the
// later rules judge it again.
func applyRulesFrom(rules []compiledRule, input string, from int) (string, []int) {
	out := input
	var fired []int
	for i, r := range rules {
		var b strings.Builder
		last, first := 0, -1
		for _, m := range r.re.FindAllStringSubmatchIndex(out, -1) {
			if m[1] <= from {
				continue
			}
			if first < 0 {
				first = m[0]
			}
			b.WriteString(out[last:m[0]])
			b.Write(r.re.ExpandString(nil, r.replacement, out, m))
			last = m[1]
		}
		if first < 0 {
			continue
		}
		b.WriteString(out[last:])
		out = b.String()
		fired = append(fired, i)
		from = min(from, first)
	}
	return out, fired
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
		if creq.Messages[i].Content != "" {
			if out, did := applyRules(rules, creq.Messages[i].Content); did {
				creq.Messages[i].Content = out
				changed = true
			}
		}
		if applyRulesToToolCalls(rules, creq.Messages[i].ToolCalls) {
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
	if applyRulesToToolCalls(rules, cresp.ToolCalls) {
		changed = true
	}
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

func applyRulesToToolCalls(rules []compiledRule, calls []adapter.CanonicalToolCall) bool {
	changed := false
	for i := range calls {
		if out, did := applyRulesToArguments(rules, calls[i].Arguments); did {
			calls[i].Arguments = out
			changed = true
		}
	}
	return changed
}

// applyRulesToArguments masks a tool call's arguments. A JSON document is
// rewritten inside its string values only, so a replacement can never break the
// syntax around them; anything that is not JSON (a custom tool's freeform
// input) is plain text and takes the rules whole.
func applyRulesToArguments(rules []compiledRule, args string) (string, bool) {
	if strings.TrimSpace(args) == "" {
		return args, false
	}
	var doc any
	dec := json.NewDecoder(strings.NewReader(args))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil || dec.More() {
		return applyRules(rules, args)
	}
	masked, changed := applyRulesToJSON(rules, doc)
	if !changed {
		return args, false
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(masked); err != nil {
		return args, false
	}
	return strings.TrimSuffix(buf.String(), "\n"), true
}

// applyRulesToJSON masks string values only; object keys are not rewritten
// because they carry the structure the receiver parses.
func applyRulesToJSON(rules []compiledRule, v any) (any, bool) {
	switch t := v.(type) {
	case string:
		return applyRules(rules, t)
	case []any:
		changed := false
		for i := range t {
			if out, did := applyRulesToJSON(rules, t[i]); did {
				t[i] = out
				changed = true
			}
		}
		return t, changed
	case map[string]any:
		changed := false
		for k, val := range t {
			if out, did := applyRulesToJSON(rules, val); did {
				t[k] = out
				changed = true
			}
		}
		return t, changed
	default:
		return v, false
	}
}
