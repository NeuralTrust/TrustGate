package adapter

import "encoding/json"

// NormalizeOpenAIRequest performs lightweight, in-place normalization of an
// OpenAI-compatible request body to fix common issues sent by third-party SDKs
// (e.g. Mistral, Cohere) that use the OpenAI wire format but omit fields that
// OpenAI strictly requires.
//
// Current normalizations:
//   - Ensures every tool_call object inside messages has "type": "function".
//     The Mistral SDK omits this field, but OpenAI returns 400 without it.
//
// The function is a no-op (returns the original body) when no changes are
// needed, so it is safe to call unconditionally on every OpenAI-bound request.
func NormalizeOpenAIRequest(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}

	msgsRaw, ok := raw["messages"]
	if !ok {
		return body
	}

	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(msgsRaw, &msgs); err != nil {
		return body
	}

	changed := false
	for i := range msgs {
		tcRaw, hasTCs := msgs[i]["tool_calls"]
		if !hasTCs {
			continue
		}

		var tcs []map[string]json.RawMessage
		if err := json.Unmarshal(tcRaw, &tcs); err != nil {
			continue
		}

		tcChanged := false
		for j := range tcs {
			typeRaw, hasType := tcs[j]["type"]
			if !hasType || isEmptyOrNull(typeRaw) {
				b, _ := json.Marshal("function")
				tcs[j]["type"] = b
				tcChanged = true
			}
		}

		if tcChanged {
			b, err := json.Marshal(tcs)
			if err == nil {
				msgs[i]["tool_calls"] = b
				changed = true
			}
		}
	}

	if !changed {
		return body
	}

	b, err := json.Marshal(msgs)
	if err != nil {
		return body
	}
	raw["messages"] = b

	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

// isEmptyOrNull returns true for nil, empty, `null`, or `""` JSON values.
func isEmptyOrNull(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	s := string(raw)
	return s == "null" || s == `""`
}
