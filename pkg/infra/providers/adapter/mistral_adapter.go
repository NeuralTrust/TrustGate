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

package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

type MistralAdapter struct {
	openai OpenAIAdapter
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

// DecodeRequest reads a Chat body. Mistral has no store, so it is not
// carried.
func (a *MistralAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	cr, err := a.openai.DecodeRequest(body)
	if cr != nil {
		cr.RequestExtensions = nil
	}
	return cr, err
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

	seed := req.Seed
	req.Seed = nil
	out, err := a.openai.EncodeRequest(req)
	req.Seed = seed
	if err != nil || seed == nil {
		return out, err
	}
	return withMistralRandomSeed(out, *seed)
}

// withMistralRandomSeed sets the seed under random_seed, Mistral's name for
// it: the API answers 422 extra_forbidden to a seed field.
func withMistralRandomSeed(body []byte, seed int64) ([]byte, error) {
	trimmed := bytes.TrimRight(body, " \t\r\n")
	if len(trimmed) < 2 || trimmed[len(trimmed)-1] != '}' {
		return nil, fmt.Errorf("mistral: request body is not a JSON object")
	}
	field := `"random_seed":` + strconv.FormatInt(seed, 10)
	if !bytes.Equal(bytes.TrimSpace(trimmed[:len(trimmed)-1]), []byte("{")) {
		field = "," + field
	}
	out := make([]byte, 0, len(trimmed)+len(field))
	out = append(out, trimmed[:len(trimmed)-1]...)
	out = append(out, field...)
	return append(out, '}'), nil
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
	return encodeCompletionsStreamChunk(chunk, false)
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

func mistralID(original string, cache map[string]string) string {
	if v, ok := cache[original]; ok {
		return v
	}
	h := sha256.Sum256([]byte(original))
	hexStr := hex.EncodeToString(h[:])
	var result []byte
	for i := 0; i < len(hexStr); i++ {
		c := hexStr[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result = append(result, c)
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
