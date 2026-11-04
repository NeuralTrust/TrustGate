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
	"encoding/json"
	"errors"
	"strings"
)

var (
	errPredictNoInstances = errors.New("instances must hold at least one item")
	errPredictNoContent   = errors.New("every instance must carry a non-empty content")
)

// VertexPredictEmbedAdapter maps the Vertex `:predict` embeddings payload
// (instances[].content in, predictions[].embeddings.values out) to and from
// the canonical embedding model.
type VertexPredictEmbedAdapter struct{}

type vertexPredictInstance struct {
	Content *string `json:"content"`
}

type vertexPredictParameters struct {
	OutputDimensionality int `json:"outputDimensionality,omitempty"`
}

type vertexPredictRequest struct {
	Model      string                   `json:"model,omitempty"`
	Instances  []vertexPredictInstance  `json:"instances"`
	Parameters *vertexPredictParameters `json:"parameters,omitempty"`
}

type vertexPredictStatistics struct {
	TokenCount float64 `json:"token_count"`
}

type vertexPredictEmbeddings struct {
	Values     []float64                `json:"values"`
	Statistics *vertexPredictStatistics `json:"statistics,omitempty"`
}

type vertexPredictPrediction struct {
	Embeddings vertexPredictEmbeddings `json:"embeddings"`
}

type vertexPredictResponse struct {
	Predictions []vertexPredictPrediction `json:"predictions"`
}

func (a *VertexPredictEmbedAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req vertexPredictRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, &RequestDecodeError{Format: FormatVertexPredictEmbed, Cause: err}
	}
	if len(req.Instances) == 0 {
		return nil, &RequestDecodeError{Format: FormatVertexPredictEmbed, Cause: errPredictNoInstances}
	}
	inputs := make([]string, 0, len(req.Instances))
	for _, instance := range req.Instances {
		if instance.Content == nil || strings.TrimSpace(*instance.Content) == "" {
			return nil, &RequestDecodeError{Format: FormatVertexPredictEmbed, Cause: errPredictNoContent}
		}
		inputs = append(inputs, *instance.Content)
	}
	emb := &CanonicalEmbeddingRequest{Model: req.Model, Inputs: inputs}
	if req.Parameters != nil {
		emb.Dimensions = req.Parameters.OutputDimensionality
	}
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalRequest{Model: req.Model, Metadata: map[string]interface{}{"embedding": json.RawMessage(raw)}}, nil
}

func (a *VertexPredictEmbedAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	emb, err := textEmbeddingFromCanonical(req)
	if err != nil {
		return nil, err
	}
	out := vertexPredictRequest{Instances: make([]vertexPredictInstance, 0, len(emb.Inputs))}
	for _, text := range emb.Inputs {
		out.Instances = append(out.Instances, vertexPredictInstance{Content: &text})
	}
	if emb.Dimensions > 0 {
		out.Parameters = &vertexPredictParameters{OutputDimensionality: emb.Dimensions}
	}
	return json.Marshal(out)
}

func (a *VertexPredictEmbedAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp vertexPredictResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	emb := &CanonicalEmbeddingResponse{Embeddings: make([][]float64, 0, len(resp.Predictions))}
	tokens := 0
	for _, prediction := range resp.Predictions {
		emb.Embeddings = append(emb.Embeddings, prediction.Embeddings.Values)
		if stats := prediction.Embeddings.Statistics; stats != nil {
			tokens += int(stats.TokenCount)
		}
	}
	emb.Usage = newCanonicalUsage(tokens, 0, tokens)
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalResponse{
		Usage: emb.Usage,
		ProviderExtensions: map[string]json.RawMessage{
			"embedding": raw,
		},
	}, nil
}

func (a *VertexPredictEmbedAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	emb, err := embeddingResponseFromCanonical(resp)
	if err != nil {
		return nil, err
	}
	out := vertexPredictResponse{Predictions: make([]vertexPredictPrediction, 0, len(emb.Embeddings))}
	for _, vec := range emb.Embeddings {
		out.Predictions = append(out.Predictions, vertexPredictPrediction{
			Embeddings: vertexPredictEmbeddings{Values: vec},
		})
	}
	return json.Marshal(out)
}

func (a *VertexPredictEmbedAdapter) DecodeStreamChunk([]byte) (*CanonicalStreamChunk, error) {
	return nil, nil
}

func (a *VertexPredictEmbedAdapter) EncodeStreamChunk(*CanonicalStreamChunk) ([][]byte, error) {
	return nil, nil
}
