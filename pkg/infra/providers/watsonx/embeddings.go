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

package watsonx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	embeddingsPath = "/ml/v1/text/embeddings"
	// watsonx.ai embeds at most this many inputs per call.
	maxEmbeddingInputs = 1000

	encodingFloat  = "float"
	encodingBase64 = "base64"
)

var _ providers.EmbeddingsClient = (*client)(nil)

// embeddingRequest is an OpenAI embeddings request reduced to what watsonx.ai
// can serve.
type embeddingRequest struct {
	model  string
	inputs []string
	base64 bool
}

type watsonxEmbeddingRequest struct {
	ModelID    string                    `json:"model_id"`
	ProjectID  string                    `json:"project_id"`
	Inputs     []string                  `json:"inputs"`
	Parameters watsonxEmbeddingParameter `json:"parameters"`
}

type watsonxEmbeddingParameter struct {
	ReturnOptions struct {
		InputText bool `json:"input_text"`
	} `json:"return_options"`
}

type watsonxEmbeddingResponse struct {
	Results []struct {
		Embedding json.RawMessage `json:"embedding"`
	} `json:"results"`
	InputTokenCount int `json:"input_token_count"`
}

// Embeddings serves an OpenAI embeddings request from the watsonx.ai
// embeddings API, splitting it into calls of at most 1000 inputs.
func (c *client) Embeddings(ctx context.Context, config *providers.Config, reqBody []byte) ([]byte, error) {
	opts, err := providers.DecodeWatsonxOptions(config.Options)
	if err != nil {
		return nil, err
	}
	req, err := parseEmbeddingRequest(reqBody, modelChoice{
		configured: strings.TrimSpace(config.Model),
		fallback:   strings.TrimSpace(config.DefaultModel),
	})
	if err != nil {
		return nil, registry.NewBackendError(http.StatusBadRequest, encodeOpenAIError(http.StatusBadRequest, "", err.Error()))
	}

	endpoint := endpointURL(opts, embeddingsPath, nil)
	httpClient := c.pool.Get(providers.ProviderWatsonx, providers.DefaultHTTPTimeout)
	vectors := make([]json.RawMessage, 0, len(req.inputs))
	tokens := 0
	for start := 0; start < len(req.inputs); start += maxEmbeddingInputs {
		batch := req.inputs[start:min(start+maxEmbeddingInputs, len(req.inputs))]
		embedded, count, err := c.embedBatch(ctx, config, endpoint, httpClient, req.model, opts.ProjectID, batch)
		if err != nil {
			return nil, err
		}
		vectors = append(vectors, embedded...)
		tokens += count
	}
	return encodeEmbeddingResponse(req.model, vectors, tokens, req.base64)
}

func (c *client) embedBatch(
	ctx context.Context,
	config *providers.Config,
	endpoint string,
	httpClient *http.Client,
	model, projectID string,
	inputs []string,
) ([]json.RawMessage, int, error) {
	body, err := json.Marshal(watsonxEmbeddingRequest{ModelID: model, ProjectID: projectID, Inputs: inputs})
	if err != nil {
		return nil, 0, fmt.Errorf("encoding watsonx embeddings request: %w", err)
	}

	resp, err := c.send(ctx, config, endpoint, body, httpClient)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, 0, fmt.Errorf("reading watsonx embeddings response: %w", err)
	}
	if registry.IsHTTPError(resp.StatusCode) {
		return nil, 0, registry.NewBackendHTTPError(resp.StatusCode, openAIErrorBody(resp.StatusCode, buf.Bytes()), resp.Header)
	}

	var parsed watsonxEmbeddingResponse
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		return nil, 0, fmt.Errorf("watsonx: decoding embeddings response: %w", err)
	}
	if len(parsed.Results) != len(inputs) {
		return nil, 0, fmt.Errorf("watsonx: embeddings response has %d vectors for %d inputs", len(parsed.Results), len(inputs))
	}
	vectors := make([]json.RawMessage, len(parsed.Results))
	for i, result := range parsed.Results {
		vectors[i] = result.Embedding
	}
	return vectors, parsed.InputTokenCount, nil
}

func parseEmbeddingRequest(body []byte, choice modelChoice) (embeddingRequest, error) {
	var in object
	if err := json.Unmarshal(body, &in); err != nil || in == nil {
		return embeddingRequest{}, errors.New("the request body must be a JSON object")
	}

	model := choice.configured
	if model == "" {
		model = jsonString(in["model"])
	}
	if model == "" {
		model = choice.fallback
	}
	if model == "" {
		return embeddingRequest{}, errNoModel
	}

	if dims := in["dimensions"]; !isNull(dims) {
		return embeddingRequest{}, errors.New("dimensions is not supported by watsonx.ai: its embedding models return vectors of their own fixed size")
	}

	req := embeddingRequest{model: model}
	switch format, _ := asString(in["encoding_format"]); format {
	case "", encodingFloat:
	case encodingBase64:
		req.base64 = true
	default:
		return embeddingRequest{}, fmt.Errorf("encoding_format must be %q or %q", encodingFloat, encodingBase64)
	}

	inputs, err := embeddingInputs(in["input"])
	if err != nil {
		return embeddingRequest{}, err
	}
	req.inputs = inputs
	return req, nil
}

// embeddingInputs accepts the text forms of an OpenAI input: one string or an
// array of strings. watsonx.ai embeds text, so token arrays are refused.
func embeddingInputs(raw json.RawMessage) ([]string, error) {
	if isNull(raw) {
		return nil, errors.New("input is required")
	}
	if s, ok := asString(raw); ok {
		return []string{s}, nil
	}
	var texts []string
	if err := json.Unmarshal(raw, &texts); err != nil {
		return nil, errors.New("input must be a string or an array of strings: watsonx.ai does not accept token arrays")
	}
	if len(texts) == 0 {
		return nil, errors.New("input must not be empty")
	}
	return texts, nil
}

type openAIEmbedding struct {
	Object    string          `json:"object"`
	Index     int             `json:"index"`
	Embedding json.RawMessage `json:"embedding"`
}

type openAIEmbeddingUsage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

type openAIEmbeddingResponse struct {
	Object string               `json:"object"`
	Data   []openAIEmbedding    `json:"data"`
	Model  string               `json:"model"`
	Usage  openAIEmbeddingUsage `json:"usage"`
}

func encodeEmbeddingResponse(model string, vectors []json.RawMessage, tokens int, asBase64 bool) ([]byte, error) {
	out := openAIEmbeddingResponse{
		Object: "list",
		Data:   make([]openAIEmbedding, len(vectors)),
		Model:  model,
		Usage:  openAIEmbeddingUsage{PromptTokens: tokens, TotalTokens: tokens},
	}
	for i, vector := range vectors {
		embedding := vector
		if asBase64 {
			encoded, err := base64Vector(vector)
			if err != nil {
				return nil, err
			}
			embedding = encoded
		}
		out.Data[i] = openAIEmbedding{Object: "embedding", Index: i, Embedding: embedding}
	}
	return json.Marshal(out)
}

// base64Vector encodes a vector the way OpenAI does for encoding_format
// base64: little-endian float32 values, standard base64, as a JSON string.
func base64Vector(vector json.RawMessage) (json.RawMessage, error) {
	var values []float64
	if err := json.Unmarshal(vector, &values); err != nil {
		return nil, fmt.Errorf("watsonx: decoding an embedding vector: %w", err)
	}
	buf := make([]byte, 4*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint32(buf[4*i:], math.Float32bits(float32(v)))
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(buf))
}
