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
	"fmt"
	"strings"
)

// GeminiEmbedAdapter is the inbound dialect of the Gemini and Vertex
// embedContent (batch false) and batchEmbedContents (batch true) actions. The
// response envelope follows the action the client called, not the number of
// vectors, so a batch of one is still answered as a batch.
type GeminiEmbedAdapter struct {
	batch bool
}

const geminiModelPrefix = "models/"

type geminiEmbedPart struct {
	Text       *string         `json:"text,omitempty"`
	InlineData json.RawMessage `json:"inlineData,omitempty"`
	FileData   json.RawMessage `json:"fileData,omitempty"`
}

type geminiEmbedContent struct {
	Parts []geminiEmbedPart `json:"parts"`
}

type geminiEmbedConfig struct {
	TaskType             string `json:"taskType,omitempty"`
	Title                string `json:"title,omitempty"`
	OutputDimensionality int    `json:"outputDimensionality,omitempty"`
}

type geminiEmbedRequest struct {
	Model                string              `json:"model,omitempty"`
	Content              *geminiEmbedContent `json:"content,omitempty"`
	TaskType             string              `json:"taskType,omitempty"`
	Title                string              `json:"title,omitempty"`
	OutputDimensionality int                 `json:"outputDimensionality,omitempty"`
	EmbedContentConfig   *geminiEmbedConfig  `json:"embedContentConfig,omitempty"`
}

type geminiBatchEmbedRequest struct {
	Model    string               `json:"model,omitempty"`
	Requests []geminiEmbedRequest `json:"requests"`
}

func (a *GeminiEmbedAdapter) format() Format {
	if a.batch {
		return FormatGeminiBatchEmbed
	}
	return FormatGeminiEmbed
}

func (a *GeminiEmbedAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	model, requests, err := a.decodeEnvelope(body)
	if err != nil {
		return nil, err
	}
	emb, err := canonicalFromGeminiRequests(requests)
	if err != nil {
		return nil, err
	}
	emb.Model = strings.TrimPrefix(model, geminiModelPrefix)
	raw, err := json.Marshal(emb)
	if err != nil {
		return nil, err
	}
	return &CanonicalRequest{Model: emb.Model, Metadata: map[string]interface{}{"embedding": json.RawMessage(raw)}}, nil
}

func (a *GeminiEmbedAdapter) decodeEnvelope(body []byte) (string, []geminiEmbedRequest, error) {
	if a.batch {
		var batch geminiBatchEmbedRequest
		if err := json.Unmarshal(body, &batch); err != nil {
			return "", nil, &RequestDecodeError{Format: a.format(), Cause: err}
		}
		if len(batch.Requests) == 0 {
			return "", nil, &UnsupportedContentError{Reason: "batchEmbedContents needs at least one request"}
		}
		return batch.Model, batch.Requests, nil
	}
	var single geminiEmbedRequest
	if err := json.Unmarshal(body, &single); err != nil {
		return "", nil, &RequestDecodeError{Format: a.format(), Cause: err}
	}
	return single.Model, []geminiEmbedRequest{single}, nil
}

func canonicalFromGeminiRequests(requests []geminiEmbedRequest) (*CanonicalEmbeddingRequest, error) {
	emb := &CanonicalEmbeddingRequest{Inputs: make([]string, 0, len(requests))}
	titles := make([]string, 0, len(requests))
	hasTitle := false
	for i, req := range requests {
		text, err := geminiEmbedText(req.Content)
		if err != nil {
			return nil, err
		}
		cfg := req.effectiveConfig()
		if cfg.OutputDimensionality < 0 {
			return nil, &UnsupportedContentError{Reason: "outputDimensionality must be positive"}
		}
		if i > 0 && (cfg.TaskType != emb.TaskType || cfg.OutputDimensionality != emb.Dimensions) {
			return nil, &UnsupportedContentError{Reason: "every request in a batch must use the same taskType and outputDimensionality"}
		}
		emb.TaskType = cfg.TaskType
		emb.Dimensions = cfg.OutputDimensionality
		emb.Inputs = append(emb.Inputs, text)
		titles = append(titles, cfg.Title)
		hasTitle = hasTitle || cfg.Title != ""
	}
	if hasTitle {
		emb.Titles = titles
	}
	return emb, nil
}

func (r geminiEmbedRequest) effectiveConfig() geminiEmbedConfig {
	cfg := geminiEmbedConfig{TaskType: r.TaskType, Title: r.Title, OutputDimensionality: r.OutputDimensionality}
	if r.EmbedContentConfig == nil {
		return cfg
	}
	if cfg.TaskType == "" {
		cfg.TaskType = r.EmbedContentConfig.TaskType
	}
	if cfg.Title == "" {
		cfg.Title = r.EmbedContentConfig.Title
	}
	if cfg.OutputDimensionality == 0 {
		cfg.OutputDimensionality = r.EmbedContentConfig.OutputDimensionality
	}
	return cfg
}

// geminiEmbedText joins the text parts of one content: Gemini returns one
// vector per content, however many parts it holds.
func geminiEmbedText(content *geminiEmbedContent) (string, error) {
	if content == nil || len(content.Parts) == 0 {
		return "", &UnsupportedContentError{Reason: "each embedding request needs a content with text parts"}
	}
	texts := make([]string, 0, len(content.Parts))
	for _, part := range content.Parts {
		if part.Text == nil || len(part.InlineData) > 0 || len(part.FileData) > 0 {
			return "", &UnsupportedContentError{Reason: "only text parts can be embedded through the gateway"}
		}
		texts = append(texts, *part.Text)
	}
	return strings.Join(texts, "\n"), nil
}

func (a *GeminiEmbedAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	emb, err := textEmbeddingFromCanonical(req)
	if err != nil {
		return nil, err
	}
	model := ""
	if emb.Model != "" {
		model = geminiModelPrefix + emb.Model
	}
	requests := make([]geminiEmbedRequest, 0, len(emb.Inputs))
	for i, text := range emb.Inputs {
		out := geminiEmbedRequest{
			Content:              &geminiEmbedContent{Parts: []geminiEmbedPart{{Text: &text}}},
			TaskType:             emb.TaskType,
			OutputDimensionality: emb.Dimensions,
		}
		if i < len(emb.Titles) {
			out.Title = emb.Titles[i]
		}
		if a.batch {
			out.Model = model
		}
		requests = append(requests, out)
	}
	if a.batch {
		return json.Marshal(geminiBatchEmbedRequest{Requests: requests})
	}
	if len(requests) != 1 {
		return nil, &UnsupportedContentError{Reason: fmt.Sprintf("embedContent embeds one content, got %d", len(requests))}
	}
	requests[0].Model = model
	return json.Marshal(requests[0])
}

func (a *GeminiEmbedAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	return (&VertexEmbedAdapter{}).DecodeResponse(body)
}

func (a *GeminiEmbedAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	emb, err := embeddingResponseFromCanonical(resp)
	if err != nil {
		return nil, err
	}
	if !a.batch {
		if len(emb.Embeddings) != 1 {
			return nil, fmt.Errorf("embedContent response needs one embedding, got %d", len(emb.Embeddings))
		}
		return json.Marshal(vertexEmbedResponse{Embedding: &vertexEmbedding{Values: emb.Embeddings[0]}})
	}
	out := struct {
		Embeddings []vertexEmbedding `json:"embeddings"`
	}{Embeddings: make([]vertexEmbedding, 0, len(emb.Embeddings))}
	for _, vec := range emb.Embeddings {
		out.Embeddings = append(out.Embeddings, vertexEmbedding{Values: vec})
	}
	return json.Marshal(out)
}

func (a *GeminiEmbedAdapter) DecodeStreamChunk([]byte) (*CanonicalStreamChunk, error) {
	return nil, nil
}

func (a *GeminiEmbedAdapter) EncodeStreamChunk(*CanonicalStreamChunk) ([][]byte, error) {
	return nil, nil
}
