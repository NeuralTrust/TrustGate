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
	"io"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func applyRules(rules []compiledRule, input string) (string, bool) {
	out, _ := applyRulesFired(rules, input)
	return out, out != input
}

// applyRulesFired is applyRules that also returns the index of every rule that
// replaced something.
func applyRulesFired(rules []compiledRule, input string) (string, []int) {
	out := input
	var fired []int
	for i, r := range rules {
		next := r.re.ReplaceAllString(out, r.replacement)
		if next != out {
			fired = append(fired, i)
		}
		out = next
	}
	return out, fired
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
	changed, _ := maskToolCalls(rules, calls)
	return changed
}

// maskToolCalls masks the arguments of calls in place and reports whether any
// changed, with the index of every rule that replaced something.
func maskToolCalls(rules []compiledRule, calls []adapter.CanonicalToolCall) (bool, []int) {
	changed := false
	var fired []int
	for i := range calls {
		out, did, ruleIdx := maskArguments(rules, calls[i].Arguments)
		fired = append(fired, ruleIdx...)
		if did {
			calls[i].Arguments = out
			changed = true
		}
	}
	return changed, fired
}

// applyRulesToArguments masks a tool call's arguments. A JSON object or array
// is rewritten in place: only the span of each string or number value the rules
// change is replaced, with the JSON encoding of the masked text. Key order,
// whitespace, escapes and every other byte stay as they came, so a request's
// before and after texts differ only where a value was masked. Rules see the
// decoded value text, not the raw JSON, and object keys are never rewritten.
// A number a rule changes becomes a JSON string. Anything else (a scalar, or
// input that is not one JSON document, such as a custom tool's freeform input)
// is plain text and takes the rules whole.
func applyRulesToArguments(rules []compiledRule, args string) (string, bool) {
	out, did, _ := maskArguments(rules, args)
	return out, did
}

func maskArguments(rules []compiledRule, args string) (string, bool, []int) {
	if strings.TrimSpace(args) == "" {
		return args, false, nil
	}
	edits, fired, ok := argumentEdits(rules, args)
	if !ok {
		out, fired := applyRulesFired(rules, args)
		return out, out != args, fired
	}
	if len(edits) == 0 {
		return args, false, fired
	}
	var b strings.Builder
	last := 0
	for _, e := range edits {
		b.WriteString(args[last:e.start])
		b.WriteString(e.text)
		last = e.end
	}
	b.WriteString(args[last:])
	return b.String(), true, fired
}

type spanEdit struct {
	start, end int
	text       string
}

type jsonFrame struct {
	object bool
	key    bool
}

// argumentEdits returns the replacements, in order, that mask the values of the
// JSON object or array in args. ok is false when args is not exactly one such
// document. fired is the index of every rule that replaced something.
func argumentEdits(rules []compiledRule, args string) ([]spanEdit, []int, bool) {
	dec := json.NewDecoder(strings.NewReader(args))
	dec.UseNumber()
	var (
		edits []spanEdit
		fired []int
		stack []jsonFrame
		prev  int
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, false
		}
		end := int(dec.InputOffset())
		start := prev
		for start < end && strings.IndexByte(" \t\r\n,:", args[start]) >= 0 {
			start++
		}
		prev = end
		if len(stack) == 0 {
			if d, isDelim := tok.(json.Delim); !isDelim || (d != '{' && d != '[') {
				return nil, nil, false
			}
		}
		if d, isDelim := tok.(json.Delim); isDelim {
			switch d {
			case '{', '[':
				if n := len(stack); n > 0 && stack[n-1].object {
					stack[n-1].key = true
				}
				stack = append(stack, jsonFrame{object: d == '{', key: d == '{'})
			default:
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 {
				if _, err := dec.Token(); err != io.EOF {
					return nil, nil, false
				}
				return edits, fired, true
			}
			continue
		}
		top := &stack[len(stack)-1]
		if top.object {
			isKey := top.key
			top.key = !top.key
			if isKey {
				continue
			}
		}
		var text string
		switch v := tok.(type) {
		case string:
			text = v
		case json.Number:
			text = v.String()
		default:
			continue
		}
		out, ruleIdx := applyRulesFired(rules, text)
		fired = append(fired, ruleIdx...)
		if out == text {
			continue
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(out); err != nil {
			return nil, nil, false
		}
		edits = append(edits, spanEdit{start: start, end: end, text: strings.TrimSuffix(buf.String(), "\n")})
	}
}
