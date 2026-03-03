package adapter

import (
	"encoding/json"
	"strings"
)

// OpenAIAdapter converts between OpenAI Chat Completions API format and the
// canonical internal model. It also acts as a dispatcher that auto-detects
// Responses API payloads and delegates decoding to the appropriate sub-adapter.
// Encoding always produces Chat Completions format; use OpenAIResponsesAdapter
// when Responses API encoding is needed.
type OpenAIAdapter struct{}

// OpenAIResponsesAdapter converts between OpenAI Responses API format and the
// canonical internal model. Registered under FormatOpenAIResponses so that the
// cross-provider pipeline (AdaptRequest/AdaptResponse/AdaptStreamChunk)
// automatically produces Responses API wire format for the client.
type OpenAIResponsesAdapter struct{}

// ---------------------------------------------------------------------------
// Format detection helpers
// ---------------------------------------------------------------------------

func isResponsesAPIRequest(body []byte) bool {
	var probe struct {
		Messages json.RawMessage `json:"messages"`
		Input    json.RawMessage `json:"input"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return false
	}
	return probe.Input != nil && probe.Messages == nil
}

func isResponsesAPIResponse(body []byte) bool {
	var probe struct {
		Object string `json:"object"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return false
	}
	return probe.Object == "response"
}

func isResponsesAPIStreamChunk(chunk []byte) bool {
	var probe struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(chunk, &probe) != nil {
		return false
	}
	return strings.HasPrefix(probe.Type, "response.")
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

func (a *OpenAIAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	if isResponsesAPIRequest(body) {
		return decodeResponsesRequest(body)
	}
	return decodeCompletionsRequest(body)
}

func (a *OpenAIAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	return encodeCompletionsRequest(req)
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

func (a *OpenAIAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	if isResponsesAPIResponse(body) {
		return decodeResponsesResponse(body)
	}
	return decodeCompletionsResponse(body)
}

func (a *OpenAIAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	return encodeCompletionsResponse(resp)
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

func (a *OpenAIAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	if isResponsesAPIStreamChunk(chunk) {
		return decodeResponsesStreamChunk(chunk)
	}
	return decodeCompletionsStreamChunk(chunk)
}

func (a *OpenAIAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	return encodeCompletionsStreamChunk(chunk)
}

// ---------------------------------------------------------------------------
// Shared helpers (used by both sub-adapters)
// ---------------------------------------------------------------------------

func decodeOpenAIToolChoice(raw json.RawMessage) *CanonicalToolChoice {
	if raw == nil {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return &CanonicalToolChoice{Type: s}
	}
	var obj struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Function.Name != "" {
		return &CanonicalToolChoice{Type: "tool", Name: obj.Function.Name}
	}
	return nil
}

func encodeOpenAIToolChoice(tc *CanonicalToolChoice) json.RawMessage {
	switch tc.Type {
	case "auto", "none", "required":
		b, _ := json.Marshal(tc.Type)
		return b
	case "any":
		b, _ := json.Marshal("required")
		return b
	case "tool":
		b, _ := json.Marshal(map[string]interface{}{
			"type":     "function",
			"function": map[string]string{"name": tc.Name},
		})
		return b
	default:
		b, _ := json.Marshal(tc.Type)
		return b
	}
}

// contentToString extracts text from a JSON content field that may be a plain
// string or an array of content-part objects.
func contentToString(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var texts []string
		for _, p := range parts {
			if p.Text != "" {
				texts = append(texts, p.Text)
			}
		}
		return strings.Join(texts, "\n")
	}
	return string(raw)
}

func stringToContent(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

func decodeStopField(raw json.RawMessage) []string {
	if raw == nil {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	return nil
}

func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// OpenAIResponsesAdapter — full ProviderAdapter for Responses API wire format
// ---------------------------------------------------------------------------

func (a *OpenAIResponsesAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	return decodeResponsesRequest(body)
}

func (a *OpenAIResponsesAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	return encodeResponsesRequest(req)
}

func (a *OpenAIResponsesAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	return decodeResponsesResponse(body)
}

func (a *OpenAIResponsesAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	return encodeResponsesResponse(resp)
}

func (a *OpenAIResponsesAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	return decodeResponsesStreamChunk(chunk)
}

func (a *OpenAIResponsesAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	return encodeResponsesStreamChunk(chunk)
}
