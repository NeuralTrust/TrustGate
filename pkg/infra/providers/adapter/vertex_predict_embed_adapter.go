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
	Content       *string `json:"content"`
	TaskType      string  `json:"task_type,omitempty"`
	TaskTypeCamel string  `json:"taskType,omitempty"`
	Title         string  `json:"title,omitempty"`
}

func (i vertexPredictInstance) taskType() string {
	if i.TaskType != "" {
		return i.TaskType
	}
	return i.TaskTypeCamel
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
	TokenCount int64 `json:"token_count"`
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
	titles := make([]string, 0, len(req.Instances))
	hasTitle := false
	for _, instance := range req.Instances {
		if instance.Content == nil || strings.TrimSpace(*instance.Content) == "" {
			return nil, &RequestDecodeError{Format: FormatVertexPredictEmbed, Cause: errPredictNoContent}
		}
		inputs = append(inputs, *instance.Content)
		titles = append(titles, instance.Title)
		hasTitle = hasTitle || instance.Title != ""
	}
	emb := &CanonicalEmbeddingRequest{Model: req.Model, Inputs: inputs, TaskType: sharedPredictTaskType(req.Instances)}
	if hasTitle {
		emb.Titles = titles
	}
	if req.Parameters != nil {
		emb.Dimensions = req.Parameters.OutputDimensionality
	}
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalRequest{Model: req.Model, Metadata: map[string]interface{}{"embedding": json.RawMessage(raw)}}, nil
}

// sharedPredictTaskType is the task type every instance asks for. The
// canonical request holds one, so instances that disagree carry none to a
// target other than Vertex, which receives the body unchanged.
func sharedPredictTaskType(instances []vertexPredictInstance) string {
	taskType := instances[0].taskType()
	for _, instance := range instances[1:] {
		if instance.taskType() != taskType {
			return ""
		}
	}
	return taskType
}

func (a *VertexPredictEmbedAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	emb, err := textEmbeddingFromCanonical(req)
	if err != nil {
		return nil, err
	}
	out := vertexPredictRequest{Instances: make([]vertexPredictInstance, 0, len(emb.Inputs))}
	for i, text := range emb.Inputs {
		instance := vertexPredictInstance{Content: &text, TaskType: emb.TaskType}
		if i < len(emb.Titles) {
			instance.Title = emb.Titles[i]
		}
		out.Instances = append(out.Instances, instance)
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
	var tokens int64
	for _, prediction := range resp.Predictions {
		emb.Embeddings = append(emb.Embeddings, prediction.Embeddings.Values)
		if stats := prediction.Embeddings.Statistics; stats != nil {
			tokens += stats.TokenCount
		}
	}
	emb.Usage = newCanonicalUsage(int(tokens), 0, int(tokens))
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
