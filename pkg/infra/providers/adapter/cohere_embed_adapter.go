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

type CanonicalEmbeddingRequest struct {
	Model     string   `json:"model,omitempty"`
	Inputs    []string `json:"inputs,omitempty"`
	InputType string   `json:"input_type,omitempty"`
}

type CanonicalEmbeddingResponse struct {
	Model      string       `json:"model,omitempty"`
	Embeddings [][]float64  `json:"embeddings,omitempty"`
	Usage      *CanonicalUsage `json:"usage,omitempty"`
}

type OpenAIEmbeddingsAdapter struct{}

type openAIEmbeddingRequest struct {
	Model string          `json:"model"`
	Input json.RawMessage `json:"input"`
}

type openAIEmbeddingResponse struct {
	Model string `json:"model"`
	Data  []struct {
		Index     int       `json:"index"`
		Embedding []float64 `json:"embedding"`
	} `json:"data"`
	Usage *struct {
		PromptTokens int `json:"prompt_tokens"`
		TotalTokens  int `json:"total_tokens"`
	} `json:"usage,omitempty"`
}

func (a *OpenAIEmbeddingsAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req openAIEmbeddingRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	inputs, err := decodeEmbeddingInputs(req.Input)
	if err != nil {
		return nil, err
	}
	emb := &CanonicalEmbeddingRequest{Model: req.Model, Inputs: inputs}
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalRequest{Model: req.Model, Metadata: map[string]interface{}{"embedding": json.RawMessage(raw)}}, nil
}

func (a *OpenAIEmbeddingsAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	emb, err := embeddingFromCanonical(req)
	if err != nil {
		return nil, err
	}
	inputRaw, err := encodeEmbeddingInputs(emb.Inputs)
	if err != nil {
		return nil, err
	}
	out := openAIEmbeddingRequest{Model: emb.Model, Input: inputRaw}
	return json.Marshal(out)
}

func (a *OpenAIEmbeddingsAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp openAIEmbeddingResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	emb := &CanonicalEmbeddingResponse{Model: resp.Model}
	for _, item := range resp.Data {
		emb.Embeddings = append(emb.Embeddings, item.Embedding)
	}
	if resp.Usage != nil {
		emb.Usage = newCanonicalUsage(resp.Usage.PromptTokens, 0, resp.Usage.TotalTokens)
	}
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalResponse{
		Model: resp.Model,
		ProviderExtensions: map[string]json.RawMessage{
			"embedding": raw,
		},
	}, nil
}

func (a *OpenAIEmbeddingsAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	emb, err := embeddingResponseFromCanonical(resp)
	if err != nil {
		return nil, err
	}
	out := openAIEmbeddingResponse{Model: emb.Model}
	for i, vec := range emb.Embeddings {
		out.Data = append(out.Data, struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		}{Index: i, Embedding: vec})
	}
	if emb.Usage != nil {
		out.Usage = &struct {
			PromptTokens int `json:"prompt_tokens"`
			TotalTokens  int `json:"total_tokens"`
		}{
			PromptTokens: emb.Usage.InputTokens,
			TotalTokens:  emb.Usage.TotalTokens,
		}
	}
	return json.Marshal(out)
}

func (a *OpenAIEmbeddingsAdapter) DecodeStreamChunk([]byte) (*CanonicalStreamChunk, error) {
	return nil, nil
}

func (a *OpenAIEmbeddingsAdapter) EncodeStreamChunk(*CanonicalStreamChunk) ([][]byte, error) {
	return nil, nil
}

type CohereEmbedAdapter struct{}

type cohereEmbedRequest struct {
	Model           string   `json:"model"`
	Texts           []string `json:"texts"`
	InputType       string   `json:"input_type"`
	EmbeddingTypes  []string `json:"embedding_types,omitempty"`
}

type cohereEmbedResponse struct {
	ID         string        `json:"id,omitempty"`
	Embeddings [][]float64   `json:"embeddings"`
}

func (a *CohereEmbedAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req cohereEmbedRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	emb := &CanonicalEmbeddingRequest{
		Model:     req.Model,
		Inputs:    req.Texts,
		InputType: req.InputType,
	}
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalRequest{Model: req.Model, Metadata: map[string]interface{}{"embedding": json.RawMessage(raw)}}, nil
}

func (a *CohereEmbedAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	emb, err := embeddingFromCanonical(req)
	if err != nil {
		return nil, err
	}
	inputType := emb.InputType
	if inputType == "" {
		inputType = "search_document"
	}
	out := cohereEmbedRequest{
		Model:          emb.Model,
		Texts:          emb.Inputs,
		InputType:      inputType,
		EmbeddingTypes: []string{"float"},
	}
	return json.Marshal(out)
}

func (a *CohereEmbedAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp cohereEmbedResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	emb := &CanonicalEmbeddingResponse{Embeddings: resp.Embeddings}
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalResponse{
		ProviderExtensions: map[string]json.RawMessage{
			"embedding": raw,
		},
	}, nil
}

func (a *CohereEmbedAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	emb, err := embeddingResponseFromCanonical(resp)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cohereEmbedResponse{Embeddings: emb.Embeddings})
}

func (a *CohereEmbedAdapter) DecodeStreamChunk([]byte) (*CanonicalStreamChunk, error) {
	return nil, nil
}

func (a *CohereEmbedAdapter) EncodeStreamChunk(*CanonicalStreamChunk) ([][]byte, error) {
	return nil, nil
}

func decodeEmbeddingInputs(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

func encodeEmbeddingInputs(inputs []string) (json.RawMessage, error) {
	if len(inputs) == 1 {
		return json.Marshal(inputs[0])
	}
	return json.Marshal(inputs)
}

func embeddingFromCanonical(req *CanonicalRequest) (*CanonicalEmbeddingRequest, error) {
	if req == nil || req.Metadata == nil {
		return &CanonicalEmbeddingRequest{Model: req.Model}, nil
	}
	raw, ok := req.Metadata["embedding"]
	if !ok {
		return &CanonicalEmbeddingRequest{Model: req.Model}, nil
	}
	var emb CanonicalEmbeddingRequest
	switch v := raw.(type) {
	case json.RawMessage:
		if err := json.Unmarshal(v, &emb); err != nil {
			return nil, err
		}
	case map[string]interface{}:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &emb); err != nil {
			return nil, err
		}
	}
	if emb.Model == "" {
		emb.Model = req.Model
	}
	return &emb, nil
}

func embeddingResponseFromCanonical(resp *CanonicalResponse) (*CanonicalEmbeddingResponse, error) {
	if resp == nil {
		return &CanonicalEmbeddingResponse{}, nil
	}
	raw, ok := resp.ProviderExtensions["embedding"]
	if !ok {
		return &CanonicalEmbeddingResponse{Model: resp.Model}, nil
	}
	var emb CanonicalEmbeddingResponse
	if err := json.Unmarshal(raw, &emb); err != nil {
		return nil, err
	}
	if emb.Model == "" {
		emb.Model = resp.Model
	}
	return &emb, nil
}

func AdaptEmbeddingRequest(registry *Registry, body []byte, source, target Format) ([]byte, error) {
	if source == target {
		return body, nil
	}
	src, err := registry.GetAdapter(source)
	if err != nil {
		return nil, err
	}
	dst, err := registry.GetAdapter(target)
	if err != nil {
		return nil, err
	}
	canonical, err := src.DecodeRequest(body)
	if err != nil {
		return nil, err
	}
	return dst.EncodeRequest(canonical)
}

func AdaptEmbeddingResponse(registry *Registry, body []byte, source, target Format) ([]byte, error) {
	if source == target {
		return body, nil
	}
	src, err := registry.GetAdapter(source)
	if err != nil {
		return nil, err
	}
	dst, err := registry.GetAdapter(target)
	if err != nil {
		return nil, err
	}
	canonical, err := dst.DecodeResponse(body)
	if err != nil {
		return nil, err
	}
	return src.EncodeResponse(canonical)
}
