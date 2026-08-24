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

package bedrock

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	bedrockTypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBedrockClient(t *testing.T) {
	assert.NotNil(t, NewBedrockClient())
}

// The body is verbatim from mistral-7b, which reports its token counts nowhere
// else: without the headers a buffered answer costs zero.
func TestWithHeaderTokenCounts(t *testing.T) {
	counted := http.Header{
		inputCountHeader:  []string{"11"},
		outputCountHeader: []string{"16"},
	}

	t.Run("adds the counts a legacy Mistral body omits", func(t *testing.T) {
		body := []byte(`{"outputs":[{"text":" OK.","stop_reason":"length"}]}`)

		merged := withHeaderTokenCounts(body, counted)

		var got struct {
			Metrics struct {
				InputTokenCount  int `json:"inputTokenCount"`
				OutputTokenCount int `json:"outputTokenCount"`
			} `json:"amazon-bedrock-invocationMetrics"`
			Outputs []json.RawMessage `json:"outputs"`
		}
		require.NoError(t, json.Unmarshal(merged, &got))
		assert.Equal(t, 11, got.Metrics.InputTokenCount)
		assert.Equal(t, 16, got.Metrics.OutputTokenCount)
		assert.Len(t, got.Outputs, 1)
	})

	t.Run("lets the body's own metrics win", func(t *testing.T) {
		body := []byte(`{"amazon-bedrock-invocationMetrics":{"inputTokenCount":7,"outputTokenCount":3}}`)

		merged := withHeaderTokenCounts(body, counted)

		var got struct {
			Metrics struct {
				InputTokenCount int `json:"inputTokenCount"`
			} `json:"amazon-bedrock-invocationMetrics"`
		}
		require.NoError(t, json.Unmarshal(merged, &got))
		assert.Equal(t, 7, got.Metrics.InputTokenCount)
	})

	t.Run("leaves the body alone when there is nothing to add", func(t *testing.T) {
		body := []byte(`{"outputs":[]}`)

		assert.Equal(t, body, withHeaderTokenCounts(body, nil))
		assert.Equal(t, body, withHeaderTokenCounts(body, http.Header{}))
		assert.Equal(t, body, withHeaderTokenCounts(body, http.Header{
			inputCountHeader: []string{"not a number"},
		}))
	})

	t.Run("keeps malformed bodies untouched", func(t *testing.T) {
		for _, body := range [][]byte{nil, []byte(""), []byte("not json"), []byte("{")} {
			assert.Equal(t, body, withHeaderTokenCounts(body, counted))
		}
	})

	t.Run("produces valid JSON for an empty object", func(t *testing.T) {
		merged := withHeaderTokenCounts([]byte(`{ }`), counted)

		var got map[string]any
		require.NoError(t, json.Unmarshal(merged, &got))
		assert.Contains(t, got, "amazon-bedrock-invocationMetrics")
	})
}

func TestNewBedrockBackendError(t *testing.T) {
	t.Run("converts AWS HTTP errors to backend errors", func(t *testing.T) {
		err := &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
				Err:      &bedrockTypes.ValidationException{Message: aws.String("Invocation of model ID is not supported.")},
			},
			RequestID: "request-id",
		}

		be := newBedrockBackendError(err)
		require.NotNil(t, be)
		assert.Equal(t, http.StatusBadRequest, be.StatusCode)
		assert.JSONEq(t, `{"error":"ValidationException","message":"Invocation of model ID is not supported."}`, string(be.Body))
	})

	t.Run("ignores non HTTP errors", func(t *testing.T) {
		assert.Nil(t, newBedrockBackendError(errors.New("network failure")))
	})

	t.Run("satisfies backend error detection", func(t *testing.T) {
		err := &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden}},
				Err:      &bedrockTypes.AccessDeniedException{Message: aws.String("access denied")},
			},
			RequestID: "request-id",
		}

		var wrapped error = newBedrockBackendError(err)
		be, ok := registry.IsBackendError(wrapped)
		require.True(t, ok)
		assert.Equal(t, http.StatusForbidden, be.StatusCode)
	})
}

func TestBedrockErrorPayload(t *testing.T) {
	t.Run("plain error", func(t *testing.T) {
		payload := bedrockErrorPayload(errors.New("boom"))
		assert.Equal(t, map[string]string{"message": "boom"}, payload)
	})
}

func TestResolveModel(t *testing.T) {
	c := &client{}

	t.Run("uses exact modelId before default model", func(t *testing.T) {
		model := c.resolveModel([]byte(`{"modelId":"eu.amazon.nova-micro-v1:0","messages":[]}`), &providers.Config{DefaultModel: "anthropic.claude-sonnet-4-20250514-v1:0"})
		assert.Equal(t, "eu.amazon.nova-micro-v1:0", model)
	})

	t.Run("falls back to config model", func(t *testing.T) {
		model := c.resolveModel([]byte(`{"messages":[]}`), &providers.Config{Model: "openai.gpt-oss-120b"})
		assert.Equal(t, "openai.gpt-oss-120b", model)
	})

	t.Run("falls back to default model", func(t *testing.T) {
		model := c.resolveModel([]byte(`{"messages":[]}`), &providers.Config{DefaultModel: "anthropic.claude-sonnet-4-20250514-v1:0"})
		assert.Equal(t, "anthropic.claude-sonnet-4-20250514-v1:0", model)
	})

	t.Run("no model returns empty", func(t *testing.T) {
		assert.Equal(t, "", c.resolveModel([]byte(`{}`), &providers.Config{}))
	})
}

func TestStripBedrockFields(t *testing.T) {
	out := stripBedrockFields([]byte(`{"modelId":"x","model":"x","stream":true,"messages":[{"role":"user"}]}`))

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &raw))
	assert.NotContains(t, raw, "modelId")
	assert.NotContains(t, raw, "model")
	assert.NotContains(t, raw, "stream")
	assert.Contains(t, raw, "messages")
}

// Inference profile IDs must survive model resolution: rewriting
// "eu.anthropic.…" to the bare model ID makes AWS reject the call, since many
// newer models cannot be invoked with on-demand throughput at all.
func TestResolveModel_PreservesInferenceProfilePrefix(t *testing.T) {
	c := &client{}
	// Bedrock-format body: encodeClaude has already removed "model", so the
	// identifier can only come from the config.
	body := []byte(`{"anthropic_version":"bedrock-2023-05-31","messages":[]}`)

	for _, model := range []string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"us.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"global.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"anthropic.claude-sonnet-4-5-20250929-v1:0",
	} {
		assert.Equal(t, model, c.resolveModel(body, &providers.Config{Model: model}))
		assert.Equal(t, model, c.resolveModel(body, &providers.Config{DefaultModel: model}))
	}
}

func TestExtractBedrockModelID(t *testing.T) {
	id, err := extractBedrockModelID([]byte(`{"modelId":"amazon.nova"}`))
	require.NoError(t, err)
	assert.Equal(t, "amazon.nova", id)

	_, err = extractBedrockModelID([]byte(`not json`))
	require.Error(t, err)
}

func TestBuildClientKey(t *testing.T) {
	assert.Equal(t, "plain-key", buildClientKey(providers.Credentials{ApiKey: "plain-key"}))

	key := buildClientKey(providers.Credentials{
		ApiKey:     "k",
		AwsBedrock: &providers.AwsBedrock{AccessKey: "AK", Region: "us-east-1", UseRole: true, RoleARN: "arn"},
	})
	assert.Equal(t, "k:AK:us-east-1:true:arn", key)
}

func TestCompletions_MissingModel(t *testing.T) {
	_, err := NewBedrockClient().Completions(context.Background(), &providers.Config{}, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model is required")
}

func TestIsTitanEmbedModel(t *testing.T) {
	assert.True(t, isTitanEmbedModel("amazon.titan-embed-text-v1"))
	assert.True(t, isTitanEmbedModel("amazon.titan-embed-text-v2:0"))
	assert.True(t, isTitanEmbedModel("eu.amazon.titan-embed-text-v2:0"))
	assert.False(t, isTitanEmbedModel("amazon.titan-text-express-v1"))
	assert.False(t, isTitanEmbedModel("anthropic.claude-sonnet-4-20250514-v1:0"))
}

func TestEmbeddings_RejectsNonTitanEmbed(t *testing.T) {
	c := NewBedrockClient().(providers.EmbeddingsClient)
	_, err := c.Embeddings(context.Background(), &providers.Config{
		Model: "amazon.titan-text-express-v1",
	}, []byte(`{"inputText":"hi"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Titan embed")
}

func TestEmbeddings_RoundTripSingle(t *testing.T) {
	var gotModel string
	var gotBody map[string]any
	c := &client{
		invoke: func(_ context.Context, model string, body []byte) ([]byte, error) {
			gotModel = model
			require.NoError(t, json.Unmarshal(body, &gotBody))
			return []byte(`{"embedding":[0.1,0.2],"inputTextTokenCount":2}`), nil
		},
	}

	resp, err := c.Embeddings(context.Background(), &providers.Config{
		Model: "eu.amazon.titan-embed-text-v2:0",
	}, []byte(`{"inputText":"hello"}`))
	require.NoError(t, err)
	assert.Equal(t, "eu.amazon.titan-embed-text-v2:0", gotModel)
	assert.Equal(t, "hello", gotBody["inputText"])
	assert.JSONEq(t, `{"embedding":[0.1,0.2],"inputTextTokenCount":2}`, string(resp))
}

func TestEmbeddings_RoundTripBatch(t *testing.T) {
	var calls int
	c := &client{
		invoke: func(_ context.Context, _ string, body []byte) ([]byte, error) {
			calls++
			var req titanEmbedInvoke
			require.NoError(t, json.Unmarshal(body, &req))
			assert.NotEmpty(t, req.InputText)
			return []byte(`{"embedding":[0.1],"inputTextTokenCount":1}`), nil
		},
	}

	resp, err := c.Embeddings(context.Background(), &providers.Config{
		Model: "amazon.titan-embed-text-v1",
	}, []byte(`{"inputTexts":["a","b"]}`))
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.JSONEq(t, `{"embeddings":[[0.1],[0.1]],"inputTextTokenCount":2}`, string(resp))
}

func TestEmbeddings_MissingModel(t *testing.T) {
	c := NewBedrockClient().(providers.EmbeddingsClient)
	_, err := c.Embeddings(context.Background(), &providers.Config{}, []byte(`{"inputText":"hi"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model is required")
}
