package adapter

import (
	"crypto/sha256"
	"encoding/hex"
)

// MistralAdapter converts between Mistral chat-completion format and the
// canonical internal model. Mistral's wire format is nearly identical to
// OpenAI, so this adapter delegates to OpenAIAdapter and applies
// Mistral-specific post-processing:
//
//   - EncodeRequest: ensures every tool has "parameters" (required by Mistral)
//     and normalises tool_call IDs to exactly 9 alphanumeric characters.
//   - All other methods delegate directly to OpenAIAdapter.
type MistralAdapter struct {
	openai OpenAIAdapter
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

func (a *MistralAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	return a.openai.DecodeRequest(body)
}

func (a *MistralAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	// Ensure every tool has a non-nil parameters schema.
	for i := range req.Tools {
		if req.Tools[i].Schema == nil {
			req.Tools[i].Schema = map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			}
		}
	}

	// Normalise tool_call IDs: Mistral requires exactly 9 chars [a-zA-Z0-9].
	idMap := map[string]string{}
	for i := range req.Messages {
		m := &req.Messages[i]
		if m.ToolCallID != "" && !isValidMistralID(m.ToolCallID) {
			m.ToolCallID = mistralID(m.ToolCallID, idMap)
		}
		for j := range m.ToolCalls {
			tc := &m.ToolCalls[j]
			if tc.ID != "" && !isValidMistralID(tc.ID) {
				tc.ID = mistralID(tc.ID, idMap)
			}
		}
	}

	return a.openai.EncodeRequest(req)
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

func (a *MistralAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	return a.openai.DecodeResponse(body)
}

func (a *MistralAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	return a.openai.EncodeResponse(resp)
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

func (a *MistralAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	return a.openai.DecodeStreamChunk(chunk)
}

func (a *MistralAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	return a.openai.EncodeStreamChunk(chunk)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isValidMistralID checks whether id is exactly 9 alphanumeric characters.
func isValidMistralID(id string) bool {
	if len(id) != 9 {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// mistralID deterministically maps an arbitrary string to a 9-character
// alphanumeric ID using SHA-256. The cache ensures the same original ID
// always maps to the same output within a single request so that
// tool_call references stay consistent.
func mistralID(original string, cache map[string]string) string {
	if v, ok := cache[original]; ok {
		return v
	}
	h := sha256.Sum256([]byte(original))
	hexStr := hex.EncodeToString(h[:])
	var result []byte
	for _, c := range hexStr {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result = append(result, byte(c))
			if len(result) == 9 {
				break
			}
		}
	}
	for len(result) < 9 {
		result = append(result, 'a')
	}
	id := string(result)
	cache[original] = id
	return id
}
