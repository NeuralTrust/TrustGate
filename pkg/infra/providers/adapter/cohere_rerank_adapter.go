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

import "encoding/json"

type cohereRerankWireRequest struct {
	Model string `json:"model"`
}

// CohereRerankAdapter maps gateway /v1/rerank payloads to Cohere v2 rerank wire format.
// The gateway speaks the same JSON shape as Cohere v2 rerank, so encode/decode are identity.
type CohereRerankAdapter struct{}

func (a *CohereRerankAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req cohereRerankWireRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	return &CanonicalRequest{
		Model:    req.Model,
		Metadata: map[string]interface{}{"rerank": body},
	}, nil
}

func (a *CohereRerankAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	if req == nil || req.Metadata == nil {
		return []byte("{}"), nil
	}
	raw, ok := req.Metadata["rerank"]
	if !ok {
		return []byte("{}"), nil
	}
	switch v := raw.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return []byte("{}"), nil
	}
}

func (a *CohereRerankAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	return &CanonicalResponse{
		ProviderExtensions: map[string]json.RawMessage{
			"rerank": body,
		},
	}, nil
}

func (a *CohereRerankAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	if resp == nil {
		return []byte("{}"), nil
	}
	raw, ok := resp.ProviderExtensions["rerank"]
	if !ok {
		return []byte("{}"), nil
	}
	return raw, nil
}

func (a *CohereRerankAdapter) DecodeStreamChunk([]byte) (*CanonicalStreamChunk, error) {
	return nil, nil
}

func (a *CohereRerankAdapter) EncodeStreamChunk(*CanonicalStreamChunk) ([][]byte, error) {
	return nil, nil
}

func AdaptRerankRequest(registry *Registry, body []byte, source, target Format) ([]byte, error) {
	if source == target {
		return body, nil
	}
	return AdaptEmbeddingRequest(registry, body, source, target)
}

func AdaptRerankResponse(registry *Registry, body []byte, source, target Format) ([]byte, error) {
	if source == target {
		return body, nil
	}
	return AdaptEmbeddingResponse(registry, body, source, target)
}
