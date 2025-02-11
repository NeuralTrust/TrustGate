package bedrock_guardrail

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	plugintypes "github.com/NeuralTrust/TrustGate/pkg/types"
)

const PluginName = "bedrock_guardrail"

// Plugin configuration
type Config struct {
	GuardrailID string `mapstructure:"guardrail_id"`
	Version     string `mapstructure:"version"`
	Actions     struct {
		Message string `mapstructure:"message"`
	} `mapstructure:"actions"`
	Credentials struct {
		AWSAccessKey string `mapstructure:"aws_access_key"`
		AWSSecretKey string `mapstructure:"aws_secret_key"`
	} `mapstructure:"credentials"`
}

// Plugin implementation
type BedrockGuardrailPlugin struct {
	logger        *logrus.Logger
	bedrockClient *bedrockruntime.Client
}

// Create new plugin instance
func NewBedrockGuardrailPlugin(logger *logrus.Logger) pluginiface.Plugin {
	return &BedrockGuardrailPlugin{
		logger: logger,
	}
}

func (p *BedrockGuardrailPlugin) Name() string {
	return PluginName
}

func (p *BedrockGuardrailPlugin) Stages() []plugintypes.Stage {
	return []plugintypes.Stage{plugintypes.PreRequest}
}

func (p *BedrockGuardrailPlugin) AllowedStages() []plugintypes.Stage {
	return []plugintypes.Stage{plugintypes.PreRequest}
}

// Execute implements the plugin logic
func (p *BedrockGuardrailPlugin) Execute(ctx context.Context, cfg plugintypes.PluginConfig, req *plugintypes.RequestContext, resp *plugintypes.ResponseContext) (*plugintypes.PluginResponse, error) {
	// Parse config
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	// Validate config
	if config.GuardrailID == "" {
		p.logger.Error("GuardrailID is required")
		return nil, fmt.Errorf("guardrail_id is required")
	}
	// If version is not specified, use default version
	if config.Version == "" {
		config.Version = "1" // Default version if not specified
	}

	// Initialize AWS SDK client if not already initialized
	if p.bedrockClient == nil {
		p.logger.Debug("Initializing AWS client")

		var awsCfg aws.Config
		var err error

		if config.Credentials.AWSAccessKey != "" && config.Credentials.AWSSecretKey != "" {
			// Use provided credentials
			p.logger.Debug("Using provided AWS credentials")
			awsCfg, err = awsconfig.LoadDefaultConfig(ctx,
				awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(
					func(ctx context.Context) (aws.Credentials, error) {
						return aws.Credentials{
							AccessKeyID:     config.Credentials.AWSAccessKey,
							SecretAccessKey: config.Credentials.AWSSecretKey,
						}, nil
					},
				)),
			)
		} else {
			// Fall back to default credentials
			p.logger.Debug("Using default AWS credentials")
			awsCfg, err = awsconfig.LoadDefaultConfig(ctx)
		}

		if err != nil {
			p.logger.WithError(err).Error("Failed to load AWS config")
			return nil, fmt.Errorf("failed to load AWS config: %v", err)
		}
		p.bedrockClient = bedrockruntime.NewFromConfig(awsCfg)
	}

	// Get content to check
	content := string(req.Body)
	if content == "" {
		p.logger.Warn("Empty content received")
		return nil, fmt.Errorf("empty content received")
	}

	// Log the content being sent to Bedrock
	p.logger.WithFields(logrus.Fields{
		"content":        content,
		"content_length": len(content),
		"guardrail_id":   config.GuardrailID,
		"version":        config.Version,
	}).Info("Content being sent to Bedrock API")

	// Prepare request for ApplyGuardrail
	contentBlock := types.GuardrailContentBlockMemberText{
		Value: types.GuardrailTextBlock{
			Text: aws.String(content),
		},
	}

	input := &bedrockruntime.ApplyGuardrailInput{
		Content:             []types.GuardrailContentBlock{&contentBlock},
		GuardrailIdentifier: aws.String(config.GuardrailID),
		GuardrailVersion:    aws.String(config.Version),
		Source:              types.GuardrailContentSourceInput,
	}

	p.logger.WithFields(logrus.Fields{
		"guardrail_id":   config.GuardrailID,
		"version":        config.Version,
		"content_length": len(content),
	}).Debug("Calling Bedrock Guardrail API")

	output, err := p.bedrockClient.ApplyGuardrail(ctx, input)
	if err != nil {
		p.logger.WithError(err).Error("Failed to call Bedrock API")
		return nil, fmt.Errorf("failed to call Bedrock API: %v", err)
	}

	p.logger.WithFields(logrus.Fields{
		"assessments": output.Assessments,
	}).Debug("Received response from Bedrock")

	// Check if content is flagged by examining the assessments
	for _, assessment := range output.Assessments {
		// Check topic policy violations
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
						Message:    fmt.Sprintf(config.Actions.Message, message),
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
						Message:    fmt.Sprintf(config.Actions.Message, message),
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
							Message:    fmt.Sprintf(config.Actions.Message, message),
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
