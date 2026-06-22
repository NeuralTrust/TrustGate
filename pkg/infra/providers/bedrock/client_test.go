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
		model := c.resolveModel([]byte(`{"modelId":"eu.amazon.nova-micro-v1:0","messages":[]}`), "anthropic.claude-sonnet-4-20250514-v1:0")
		assert.Equal(t, "eu.amazon.nova-micro-v1:0", model)
	})

	t.Run("falls back to default model", func(t *testing.T) {
		model := c.resolveModel([]byte(`{"messages":[]}`), "anthropic.claude-sonnet-4-20250514-v1:0")
		assert.Equal(t, "anthropic.claude-sonnet-4-20250514-v1:0", model)
	})

	t.Run("no model returns empty", func(t *testing.T) {
		assert.Equal(t, "", c.resolveModel([]byte(`{}`), ""))
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

func TestBedrockModelID(t *testing.T) {
	assert.Equal(t, "anthropic.claude-3", bedrockModelID("eu.anthropic.claude-3"))
	assert.Equal(t, "us.deepseek.r1", bedrockModelID("us.deepseek.r1"), "us. prefix is preserved")
	assert.Equal(t, "amazon.titan", bedrockModelID("amazon.titan"))
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
