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

type BedrockTitanEmbedAdapter struct{}

type titanEmbedRequest struct {
	InputText  string   `json:"inputText,omitempty"`
	InputTexts []string `json:"inputTexts,omitempty"`
}

type titanEmbedResponse struct {
	Embedding           []float64   `json:"embedding,omitempty"`
	Embeddings          [][]float64 `json:"embeddings,omitempty"`
	InputTextTokenCount int         `json:"inputTextTokenCount,omitempty"`
}

func (a *BedrockTitanEmbedAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req titanEmbedRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	inputs := req.InputTexts
	if len(inputs) == 0 && req.InputText != "" {
		inputs = []string{req.InputText}
	}
	emb := &CanonicalEmbeddingRequest{Inputs: inputs}
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalRequest{Metadata: map[string]interface{}{"embedding": json.RawMessage(raw)}}, nil
}

func (a *BedrockTitanEmbedAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	emb, err := embeddingFromCanonical(req)
	if err != nil {
		return nil, err
	}
	if len(emb.Inputs) == 1 {
		return json.Marshal(titanEmbedRequest{InputText: emb.Inputs[0]})
	}
	return json.Marshal(titanEmbedRequest{InputTexts: emb.Inputs})
}

func (a *BedrockTitanEmbedAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp titanEmbedResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	emb := &CanonicalEmbeddingResponse{}
	switch {
	case len(resp.Embeddings) > 0:
		emb.Embeddings = resp.Embeddings
	case len(resp.Embedding) > 0:
		emb.Embeddings = [][]float64{resp.Embedding}
	}
	if resp.InputTextTokenCount > 0 {
		emb.Usage = newCanonicalUsage(resp.InputTextTokenCount, 0, resp.InputTextTokenCount)
	}
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalResponse{
		ProviderExtensions: map[string]json.RawMessage{
			"embedding": raw,
		},
		Usage: emb.Usage,
	}, nil
}

func (a *BedrockTitanEmbedAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	emb, err := embeddingResponseFromCanonical(resp)
	if err != nil {
		return nil, err
	}
	out := titanEmbedResponse{}
	if emb.Usage != nil {
		out.InputTextTokenCount = emb.Usage.InputTokens
	}
	if len(emb.Embeddings) == 1 {
		out.Embedding = emb.Embeddings[0]
		return json.Marshal(out)
	}
	out.Embeddings = emb.Embeddings
	return json.Marshal(out)
}

func (a *BedrockTitanEmbedAdapter) DecodeStreamChunk([]byte) (*CanonicalStreamChunk, error) {
	return nil, nil
}

func (a *BedrockTitanEmbedAdapter) EncodeStreamChunk(*CanonicalStreamChunk) ([][]byte, error) {
	return nil, nil
}
