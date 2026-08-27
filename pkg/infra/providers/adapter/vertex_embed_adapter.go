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

type VertexEmbedAdapter struct{}

type vertexEmbedPart struct {
	Text string `json:"text"`
}

type vertexEmbedContent struct {
	Parts []vertexEmbedPart `json:"parts"`
}

type vertexEmbedRequest struct {
	Content *vertexEmbedContent `json:"content,omitempty"`
}

type vertexBatchEmbedRequest struct {
	Requests []vertexEmbedRequest `json:"requests"`
}

type vertexEmbedding struct {
	Values []float64 `json:"values"`
}

type vertexEmbedResponse struct {
	Embedding  *vertexEmbedding  `json:"embedding,omitempty"`
	Embeddings []vertexEmbedding `json:"embeddings,omitempty"`
}

func (a *VertexEmbedAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var batch vertexBatchEmbedRequest
	if err := json.Unmarshal(body, &batch); err != nil {
		return nil, err
	}
	inputs := make([]string, 0, len(batch.Requests))
	if len(batch.Requests) > 0 {
		for _, req := range batch.Requests {
			inputs = append(inputs, textsFromVertexContent(req.Content)...)
		}
	} else {
		var single vertexEmbedRequest
		if err := json.Unmarshal(body, &single); err != nil {
			return nil, err
		}
		inputs = textsFromVertexContent(single.Content)
	}
	emb := &CanonicalEmbeddingRequest{Inputs: inputs}
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalRequest{Metadata: map[string]interface{}{"embedding": json.RawMessage(raw)}}, nil
}

func (a *VertexEmbedAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	emb, err := embeddingFromCanonical(req)
	if err != nil {
		return nil, err
	}
	if len(emb.Inputs) == 1 {
		return json.Marshal(vertexEmbedRequest{Content: vertexContentFromText(emb.Inputs[0])})
	}
	out := vertexBatchEmbedRequest{Requests: make([]vertexEmbedRequest, 0, len(emb.Inputs))}
	for _, text := range emb.Inputs {
		out.Requests = append(out.Requests, vertexEmbedRequest{Content: vertexContentFromText(text)})
	}
	return json.Marshal(out)
}

func (a *VertexEmbedAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp vertexEmbedResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	emb := &CanonicalEmbeddingResponse{}
	switch {
	case len(resp.Embeddings) > 0:
		for _, item := range resp.Embeddings {
			emb.Embeddings = append(emb.Embeddings, item.Values)
		}
	case resp.Embedding != nil:
		emb.Embeddings = [][]float64{resp.Embedding.Values}
	}
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

func (a *VertexEmbedAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	emb, err := embeddingResponseFromCanonical(resp)
	if err != nil {
		return nil, err
	}
	if len(emb.Embeddings) == 1 {
		return json.Marshal(vertexEmbedResponse{
			Embedding: &vertexEmbedding{Values: emb.Embeddings[0]},
		})
	}
	out := vertexEmbedResponse{Embeddings: make([]vertexEmbedding, 0, len(emb.Embeddings))}
	for _, vec := range emb.Embeddings {
		out.Embeddings = append(out.Embeddings, vertexEmbedding{Values: vec})
	}
	return json.Marshal(out)
}

func (a *VertexEmbedAdapter) DecodeStreamChunk([]byte) (*CanonicalStreamChunk, error) {
	return nil, nil
}

func (a *VertexEmbedAdapter) EncodeStreamChunk(*CanonicalStreamChunk) ([][]byte, error) {
	return nil, nil
}

func vertexContentFromText(text string) *vertexEmbedContent {
	return &vertexEmbedContent{Parts: []vertexEmbedPart{{Text: text}}}
}

func textsFromVertexContent(content *vertexEmbedContent) []string {
	if content == nil {
		return nil
	}
	out := make([]string, 0, len(content.Parts))
	for _, part := range content.Parts {
		if part.Text != "" {
			out = append(out, part.Text)
		}
	}
	return out
}
