package bedrock

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	bedrockTypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBedrockUpstreamError(t *testing.T) {
	t.Run("converts AWS HTTP errors to upstream errors", func(t *testing.T) {
		err := &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{
					Response: &http.Response{StatusCode: http.StatusBadRequest},
				},
				Err: &bedrockTypes.ValidationException{
					Message: aws.String("Invocation of model ID is not supported."),
				},
			},
			RequestID: "request-id",
		}

		upstreamErr := newBedrockUpstreamError(err)

		require.NotNil(t, upstreamErr)
		assert.Equal(t, http.StatusBadRequest, upstreamErr.StatusCode)
		assert.JSONEq(t, `{
			"error": "ValidationException",
			"message": "Invocation of model ID is not supported."
		}`, string(upstreamErr.Body))
	})

	t.Run("ignores non HTTP errors", func(t *testing.T) {
		upstreamErr := newBedrockUpstreamError(errors.New("network failure"))

		assert.Nil(t, upstreamErr)
	})

	t.Run("satisfies upstream error detection", func(t *testing.T) {
		err := &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{
					Response: &http.Response{StatusCode: http.StatusForbidden},
				},
				Err: &bedrockTypes.AccessDeniedException{
					Message: aws.String("access denied"),
				},
			},
			RequestID: "request-id",
		}

		var wrappedErr error = newBedrockUpstreamError(err)
		upstreamErr, ok := domainUpstream.IsUpstreamError(wrappedErr)

		require.True(t, ok)
		assert.Equal(t, http.StatusForbidden, upstreamErr.StatusCode)
	})
}

func TestResolveModel(t *testing.T) {
	t.Run("uses exact modelId before default model", func(t *testing.T) {
		body := []byte(`{"modelId":"eu.amazon.nova-micro-v1:0","messages":[]}`)

		model := (&client{}).resolveModel(body, "anthropic.claude-sonnet-4-20250514-v1:0")

		assert.Equal(t, "eu.amazon.nova-micro-v1:0", model)
	})

	t.Run("falls back to default model", func(t *testing.T) {
		body := []byte(`{"messages":[]}`)

		model := (&client{}).resolveModel(body, "anthropic.claude-sonnet-4-20250514-v1:0")

		assert.Equal(t, "anthropic.claude-sonnet-4-20250514-v1:0", model)
	})
}

func TestStripBedrockFields(t *testing.T) {
	body := []byte(`{
		"modelId": "eu.amazon.nova-micro-v1:0",
		"model": "eu.amazon.nova-micro-v1:0",
		"stream": true,
		"messages": [{"role":"user","content":[{"text":"hi"}]}]
	}`)

	out := stripBedrockFields(body)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &raw))
	assert.NotContains(t, raw, "modelId")
	assert.NotContains(t, raw, "model")
	assert.NotContains(t, raw, "stream")
	assert.Contains(t, raw, "messages")
}
