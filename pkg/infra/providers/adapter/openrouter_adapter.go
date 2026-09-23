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
	"context"
	"encoding/json"
	"log/slog"
)

var openRouterRequestKeys = []string{"provider", "models", "transforms", "route"}

var openRouterResponseKeys = []string{"provider"}

// OpenRouterAdapter wraps OpenAIAdapter and preserves OpenRouter routing fields.
type OpenRouterAdapter struct {
	openai OpenAIAdapter
}

func (a *OpenRouterAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	cr, err := a.openai.DecodeRequest(body)
	if err != nil {
		return nil, err
	}
	cr.RequestExtensions = extractOpenRouterKeys(body, openRouterRequestKeys)
	return cr, nil
}

func (a *OpenRouterAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out, err := a.openai.EncodeRequest(req)
	if err != nil {
		return nil, err
	}
	return mergeJSONExtensions(out, req.RequestExtensions)
}

func (a *OpenRouterAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	cr, err := a.openai.DecodeResponse(body)
	if err != nil {
		return nil, err
	}
	if cr.Usage != nil {
		logOpenRouterBilling(body)
	}
	ext := extractOpenRouterKeys(body, openRouterResponseKeys)
	if len(ext) == 0 {
		return cr, nil
	}
	if cr.ProviderExtensions == nil {
		cr.ProviderExtensions = make(map[string]json.RawMessage, len(ext))
	}
	for k, v := range ext {
		cr.ProviderExtensions[k] = v
	}
	return cr, nil
}

func (a *OpenRouterAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	out, err := a.openai.EncodeResponse(resp)
	if err != nil {
		return nil, err
	}
	return mergeJSONExtensions(out, resp.ProviderExtensions)
}

func (a *OpenRouterAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	if isSSECommentLine(chunk) {
		return nil, nil
	}
	payload := sseJSONPayload(chunk)
	if payload == nil {
		return nil, nil
	}

	sc, err := a.openai.DecodeStreamChunk(payload)
	if err != nil || sc == nil || sc.UpstreamErrorOnly() {
		return sc, err
	}
	if sc.Usage != nil {
		logOpenRouterBilling(payload)
	}
	ext := extractOpenRouterKeys(payload, openRouterResponseKeys)
	if len(ext) == 0 {
		return sc, nil
	}
	if sc.ProviderExtensions == nil {
		sc.ProviderExtensions = make(map[string]json.RawMessage, len(ext))
	}
	for k, v := range ext {
		sc.ProviderExtensions[k] = v
	}
	return sc, nil
}

func (a *OpenRouterAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	lines, err := a.openai.EncodeStreamChunk(chunk)
	if err != nil || len(lines) == 0 || chunk == nil || len(chunk.ProviderExtensions) == 0 {
		return lines, err
	}

	for i, line := range lines {
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		merged, merr := mergeJSONExtensions(payload, chunk.ProviderExtensions)
		if merr != nil {
			return nil, merr
		}
		lines[i] = append([]byte("data: "), merged...)
		break
	}
	return lines, nil
}

type openRouterBilling struct {
	Usage struct {
		Cost          *float64 `json:"cost"`
		CacheDiscount *float64 `json:"cache_discount"`
	} `json:"usage"`
	CacheDiscount *float64 `json:"cache_discount"`
}

func logOpenRouterBilling(body []byte) {
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	var b openRouterBilling
	if err := json.Unmarshal(body, &b); err != nil {
		return
	}
	discount := b.Usage.CacheDiscount
	if discount == nil {
		discount = b.CacheDiscount
	}
	if b.Usage.Cost == nil && discount == nil {
		return
	}
	attrs := make([]any, 0, 2)
	if b.Usage.Cost != nil {
		attrs = append(attrs, slog.Float64("cost", *b.Usage.Cost))
	}
	if discount != nil {
		attrs = append(attrs, slog.Float64("cache_discount", *discount))
	}
	slog.Debug("openrouter reported billing", attrs...)
}

func extractOpenRouterKeys(body []byte, keys []string) map[string]json.RawMessage {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	ext := make(map[string]json.RawMessage)
	for _, k := range keys {
		if v, ok := raw[k]; ok && len(v) > 0 && !isEmptyOrNull(v) {
			ext[k] = v
		}
	}
	if len(ext) == 0 {
		return nil
	}
	return ext
}

func mergeJSONExtensions(base []byte, extensions map[string]json.RawMessage) ([]byte, error) {
	if len(extensions) == 0 {
		return base, nil
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(base, &out); err != nil {
		return nil, err
	}
	for k, v := range extensions {
		out[k] = v
	}
	return json.Marshal(out)
}

func isSSECommentLine(line []byte) bool {
	trimmed := bytes.TrimSpace(line)
	return len(trimmed) > 0 && trimmed[0] == ':'
}

func sseJSONPayload(line []byte) []byte {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil
	}
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		payload := bytes.TrimSpace(bytes.TrimPrefix(trimmed, []byte("data:")))
		if bytes.Equal(payload, []byte("[DONE]")) {
			return nil
		}
		return payload
	}
	return trimmed
}
