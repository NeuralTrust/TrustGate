package bedrock_guardrail_test

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/bedrock_guardrail"
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
		config.AWSConfig{
			AccessKey: "test-access-key",
			SecretKey: "test-secret-key",
			Region:    "us-west-2",
		},
	)

	cf := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
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
	plugin := bedrock_guardrail.NewBedrockGuardrailPlugin(logger, client, config.AWSConfig{
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
		Region:    "us-west-2",
	})

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

	conf := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"guardrail_id": "test-guardrail",
			"version":      "1",
			"actions":      map[string]interface{}{"message": "Blocked: %s"},
		},
	}

	req := &plugintypes.RequestContext{Body: []byte("test content")}
	resp := &plugintypes.ResponseContext{}
	result, err := plugin.Execute(context.Background(), conf, req, resp)

	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestExecute_ContentAllowed(t *testing.T) {
	logger := logrus.New()
	client := new(mocks.Client)
	plugin := bedrock_guardrail.NewBedrockGuardrailPlugin(logger, client, config.AWSConfig{
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
		Region:    "us-west-2",
	})

	client.On("ApplyGuardrail", mock.Anything, mock.Anything).Return(&bedrockruntime.ApplyGuardrailOutput{
		Assessments: []types.GuardrailAssessment{},
	}, nil)

	conf := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"guardrail_id": "test-guardrail",
			"version":      "1",
			"actions":      map[string]interface{}{"message": "Blocked: %s"},
		},
	}

	req := &plugintypes.RequestContext{Body: []byte("test content")}
	resp := &plugintypes.ResponseContext{}
	result, err := plugin.Execute(context.Background(), conf, req, resp)

	assert.NotNil(t, result)
	assert.NoError(t, err)
	assert.Equal(t, 200, result.StatusCode)
}

func TestExecute_BedrockAPIFailure(t *testing.T) {
	logger := logrus.New()
	client := new(mocks.Client)
	plugin := bedrock_guardrail.NewBedrockGuardrailPlugin(logger, client, config.AWSConfig{
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
		Region:    "us-west-2",
	})

	client.On("ApplyGuardrail", mock.Anything, mock.Anything).Return(nil, errors.New("API failure"))

	conf := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"guardrail_id": "test-guardrail",
			"version":      "1",
			"actions":      map[string]interface{}{"message": "Blocked: %s"},
		},
	}

	req := &plugintypes.RequestContext{Body: []byte("test content")}
	resp := &plugintypes.ResponseContext{}
	result, err := plugin.Execute(context.Background(), conf, req, resp)

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to call Bedrock API")
}
