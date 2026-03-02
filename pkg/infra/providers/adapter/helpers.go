package adapter

import "encoding/json"

// ExtractUserInputGeneric attempts to find user input from common JSON fields
// when no provider-specific adapter is available.
// It probes, in order: messages[-1].content (last user), input, prompt.
func ExtractUserInputGeneric(body []byte) string {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return ""
	}

	if raw, ok := root["messages"]; ok {
		var msgs []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}
		if json.Unmarshal(raw, &msgs) == nil {
			for i := len(msgs) - 1; i >= 0; i-- {
				if msgs[i].Role == "user" && msgs[i].Content != "" {
					return msgs[i].Content
				}
			}
		}
	}

	if raw, ok := root["input"]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}

	if raw, ok := root["prompt"]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}

	return ""
}

// ExtractAssistantOutputGeneric attempts to find assistant output from common
// JSON fields when no provider-specific adapter is available.
// It probes, in order: choices[0].message.content, content, output.
func ExtractAssistantOutputGeneric(body []byte) string {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return ""
	}

	if raw, ok := root["choices"]; ok {
		var choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(raw, &choices) == nil && len(choices) > 0 && choices[0].Message.Content != "" {
			return choices[0].Message.Content
		}
	}

	if raw, ok := root["content"]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}

	if raw, ok := root["output"]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}

	return ""
}
