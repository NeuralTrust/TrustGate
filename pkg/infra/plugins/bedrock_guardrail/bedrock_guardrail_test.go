package bedrock_guardrail_test

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/bedrock_guardrail"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	plugintypes "github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestValidateConfig(t *testing.T) {
	logger := logrus.New()
	client := new(mocks.Client)
	plugin := bedrock_guardrail.NewBedrockGuardrailPlugin(
		logger,
		client,
	)

	cf := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"aws_access_key": "$AWS_ACCESS_KEY",
				"aws_secret_key": "$AWS_SECRET_KEY",
				"aws_region":     "$AWS_REGION",
			},
			"guardrail_id": "test-guardrail",
			"version":      "1",
			"actions":      map[string]interface{}{"message": "Blocked: %s"},
		},
	}

	err := plugin.ValidateConfig(cf)
	assert.NoError(t, err)
}

func TestExecute_ContentBlockedByPolicy(t *testing.T) {
	logger := logrus.New()
	client := new(mocks.Client)
	plugin := bedrock_guardrail.NewBedrockGuardrailPlugin(logger, client)
	client.On("BuildClient", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(client, nil)
	client.On("ApplyGuardrail", mock.Anything, mock.Anything).Return(&bedrockruntime.ApplyGuardrailOutput{
		Assessments: []types.GuardrailAssessment{
			{
				TopicPolicy: &types.GuardrailTopicPolicyAssessment{
					Topics: []types.GuardrailTopic{
						{Name: aws.String("Hate Speech"), Action: "BLOCKED", Type: "DENY"},
					},
				},
			},
		},
	}, nil)

	conf := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"aws_access_key":    "$AWS_ACCESS_KEY",
				"aws_secret_key":    "$AWS_SECRET_KEY",
				"aws_session_token": "$AWS_SESSION_TOKEN",
				"aws_region":        "$AWS_REGION",
			},
			"guardrail_id": "test-guardrail",
			"version":      "1",
			"actions":      map[string]interface{}{"message": "Blocked: %s"},
		},
	}

	req := &plugintypes.RequestContext{Body: []byte("test content")}
	resp := &plugintypes.ResponseContext{}
	result, err := plugin.Execute(context.Background(), conf, req, resp, metrics.NewEventContext("", "", nil))

	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestExecute_ContentAllowed(t *testing.T) {
	logger := logrus.New()
	client := new(mocks.Client)
	plugin := bedrock_guardrail.NewBedrockGuardrailPlugin(logger, client)

	client.On("ApplyGuardrail", mock.Anything, mock.Anything).Return(&bedrockruntime.ApplyGuardrailOutput{
		Assessments: []types.GuardrailAssessment{},
	}, nil)

	client.On("BuildClient", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(client, nil)

	conf := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"guardrail_id": "test-guardrail",
			"version":      "1",
			"actions":      map[string]interface{}{"message": "Blocked: %s"},
		},
	}

	req := &plugintypes.RequestContext{Body: []byte("test content")}
	resp := &plugintypes.ResponseContext{}
	result, err := plugin.Execute(context.Background(), conf, req, resp, metrics.NewEventContext("", "", nil))

	assert.NotNil(t, result)
	assert.NoError(t, err)
	assert.Equal(t, 200, result.StatusCode)
}

func TestExecute_BedrockAPIFailure(t *testing.T) {
	logger := logrus.New()
	client := new(mocks.Client)
	plugin := bedrock_guardrail.NewBedrockGuardrailPlugin(logger, client)
	client.On("BuildClient", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(client, nil)
	client.On("ApplyGuardrail", mock.Anything, mock.Anything).Return(nil, errors.New("API failure"))

	conf := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"guardrail_id": "test-guardrail",
			"version":      "1",
			"actions":      map[string]interface{}{"message": "Blocked: %s"},
		},
	}

	req := &plugintypes.RequestContext{Body: []byte("test content")}
	resp := &plugintypes.ResponseContext{}
	result, err := plugin.Execute(context.Background(), conf, req, resp, metrics.NewEventContext("", "", nil))

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to call Bedrock API")
}
