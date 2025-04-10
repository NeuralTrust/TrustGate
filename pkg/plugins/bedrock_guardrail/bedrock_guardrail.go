package bedrock_guardrail

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	plugintypes "github.com/NeuralTrust/TrustGate/pkg/types"
)

const PluginName = "bedrock_guardrail"

type Config struct {
	GuardrailID string      `mapstructure:"guardrail_id"`
	Version     string      `mapstructure:"version"`
	Actions     Actions     `mapstructure:"actions"`
	Credentials Credentials `mapstructure:"credentials"`
}

type Credentials struct {
	AWSAccessKey string `mapstructure:"aws_access_key"`
	AWSSecretKey string `mapstructure:"aws_secret_key"`
	AWSRegion    string `mapstructure:"aws_region"`
}
type Actions struct {
	Message string `mapstructure:"message"`
}

type BedrockGuardrailPlugin struct {
	logger *logrus.Logger
	client bedrock.Client
}

func NewBedrockGuardrailPlugin(
	logger *logrus.Logger,
	client bedrock.Client,
) pluginiface.Plugin {
	return &BedrockGuardrailPlugin{
		logger: logger,
		client: client,
	}
}

func (p *BedrockGuardrailPlugin) ValidateConfig(config plugintypes.PluginConfig) error {

	var conf Config
	if err := mapstructure.Decode(config.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return fmt.Errorf("failed to decode config: %v", err)
	}
	if conf.GuardrailID == "" {
		return fmt.Errorf("aws GuardrailID must be specified")
	}
	if conf.Credentials.AWSAccessKey == "" {
		return fmt.Errorf("aws Access key must be specified")
	}
	if conf.Credentials.AWSSecretKey == "" {
		return fmt.Errorf("aws Secret key must be specified")
	}
	if conf.Credentials.AWSRegion == "" {
		return fmt.Errorf("aws Region must be specified")
	}

	return nil
}

func (p *BedrockGuardrailPlugin) Name() string {
	return PluginName
}

func (p *BedrockGuardrailPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *BedrockGuardrailPlugin) Stages() []plugintypes.Stage {
	return []plugintypes.Stage{plugintypes.PreRequest}
}

func (p *BedrockGuardrailPlugin) AllowedStages() []plugintypes.Stage {
	return []plugintypes.Stage{plugintypes.PreRequest}
}

func (p *BedrockGuardrailPlugin) Execute(
	ctx context.Context,
	cfg plugintypes.PluginConfig,
	req *plugintypes.RequestContext,
	resp *plugintypes.ResponseContext,
	collector *metrics.Collector,
) (*plugintypes.PluginResponse, error) {
	// Parse config
	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	// Validate config
	if conf.GuardrailID == "" {
		p.logger.Error("GuardrailID is required")
		return nil, fmt.Errorf("guardrail_id is required")
	}
	// If version is not specified, use default version
	if conf.Version == "" {
		conf.Version = "1" // Default version if not specified
	}

	// Get content to check
	content := string(req.Body)
	if content == "" {
		p.logger.Warn("empty content received for bedrock guardrail check")
		return &plugintypes.PluginResponse{
			StatusCode: 200,
			Message:    "Content allowed",
		}, nil
	}

	// Log the content being sent to Bedrock
	p.logger.WithFields(logrus.Fields{
		"content":        content,
		"content_length": len(content),
		"guardrail_id":   conf.GuardrailID,
		"version":        conf.Version,
	}).Info("Content being sent to Bedrock API")

	// Prepare request for ApplyGuardrail
	contentBlock := types.GuardrailContentBlockMemberText{
		Value: types.GuardrailTextBlock{
			Text: aws.String(content),
		},
	}

	input := &bedrockruntime.ApplyGuardrailInput{
		Content:             []types.GuardrailContentBlock{&contentBlock},
		GuardrailIdentifier: aws.String(conf.GuardrailID),
		GuardrailVersion:    aws.String(conf.Version),
		Source:              types.GuardrailContentSourceInput,
	}

	p.logger.WithFields(logrus.Fields{
		"guardrail_id":   conf.GuardrailID,
		"version":        conf.Version,
		"content_length": len(content),
	}).Debug("Calling Bedrock Guardrail API")

	bedrockClient, err := p.client.BuildClient(
		ctx,
		conf.Credentials.AWSAccessKey,
		conf.Credentials.AWSSecretKey,
		conf.Credentials.AWSRegion,
	)
	if err != nil {
		p.logger.WithError(err).Error("Failed to create Bedrock client")
		return nil, fmt.Errorf("failed to create Bedrock client: %v", err)
	}

	output, err := bedrockClient.ApplyGuardrail(ctx, input)
	if err != nil {
		p.logger.WithError(err).Error("Failed to call Bedrock API")
		return nil, fmt.Errorf("failed to call Bedrock API: %v", err)
	}

	p.logger.WithFields(logrus.Fields{
		"assessments": output.Assessments,
	}).Debug("Received response from Bedrock")

	// Check if content is flagged by examining the assessments
	for _, assessment := range output.Assessments {
		if assessment.TopicPolicy != nil && len(assessment.TopicPolicy.Topics) > 0 {
			for _, topic := range assessment.TopicPolicy.Topics {
				if topic.Action == "BLOCKED" && topic.Type == "DENY" {
					message := fmt.Sprintf("Content blocked: Topic '%s' is not allowed", *topic.Name)
					p.logger.WithFields(logrus.Fields{
						"topic":  *topic.Name,
						"type":   topic.Type,
						"action": topic.Action,
					}).Info("Content blocked due to topic policy violation")
					return nil, &plugintypes.PluginError{
						StatusCode: 403,
						Message:    fmt.Sprintf(conf.Actions.Message, message),
						Err:        fmt.Errorf("content blocked by guardrail: topic policy violation"),
					}
				}
			}
		}

		// Check content policy violations
		if assessment.ContentPolicy != nil && len(assessment.ContentPolicy.Filters) > 0 {
			for _, filter := range assessment.ContentPolicy.Filters {
				if filter.Action == "REJECT" {
					message := "Content blocked: Potentially harmful content detected"
					if filter.Type != "" {
						message = fmt.Sprintf("Content blocked: %s", filter.Type)
					}
					p.logger.WithFields(logrus.Fields{
						"filter_type": filter.Type,
						"action":      filter.Action,
					}).Info("Content blocked due to content policy violation")
					return nil, &plugintypes.PluginError{
						StatusCode: 403,
						Message:    fmt.Sprintf(conf.Actions.Message, message),
						Err:        fmt.Errorf("content blocked by guardrail"),
					}
				}
			}
		}

		// Check sensitive information policy violations
		if assessment.SensitiveInformationPolicy != nil {
			if len(assessment.SensitiveInformationPolicy.PiiEntities) > 0 {
				for _, entity := range assessment.SensitiveInformationPolicy.PiiEntities {
					if entity.Action == "REJECT" {
						message := fmt.Sprintf("Content blocked: Sensitive information detected (%s)", *entity.Match)
						p.logger.WithFields(logrus.Fields{
							"entity_type": entity.Type,
							"action":      entity.Action,
						}).Info("Content blocked due to sensitive information violation")
						return nil, &plugintypes.PluginError{
							StatusCode: 403,
							Message:    fmt.Sprintf(conf.Actions.Message, message),
							Err:        fmt.Errorf("content blocked by guardrail: sensitive information"),
						}
					}
				}
			}
		}
	}

	// Content allowed
	p.logger.Info("Content allowed - no policy violations detected")
	return &plugintypes.PluginResponse{
		StatusCode: 200,
		Message:    "Content allowed",
	}, nil
}
