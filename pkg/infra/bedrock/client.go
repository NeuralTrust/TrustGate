package bedrock

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Client --dir=. --output=../../../mocks --filename=bedrock_client_mock.go --case=underscore --with-expecter
type Client interface {
	ApplyGuardrail(
		ctx context.Context,
		params *bedrockruntime.ApplyGuardrailInput,
		optFns ...func(*bedrockruntime.Options),
	) (*bedrockruntime.ApplyGuardrailOutput, error)
	BuildClient(ctx context.Context, accessKey, secretKey, region string, useRole bool, roleARN, sessionName string) (Client, error)
}

type client struct {
	client *bedrockruntime.Client
	logger *logrus.Logger
}

func NewClient(logger *logrus.Logger) (Client, error) {
	return &client{
		logger: logger,
	}, nil
}

func (c *client) BuildClient(
	ctx context.Context,
	accessKey, secretKey, region string,
	useRole bool,
	roleARN, sessionName string,
) (Client, error) {
	var awsCfg aws.Config
	var err error

	if useRole && roleARN != "" {
		c.logger.WithFields(logrus.Fields{
			"role_arn":     roleARN,
			"session_name": sessionName,
		}).Info("Using role-based authentication for Bedrock client")

		baseCfg, err := awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(
				func(ctx context.Context) (aws.Credentials, error) {
					return aws.Credentials{
						AccessKeyID:     accessKey,
						SecretAccessKey: secretKey,
					}, nil
				},
			)),
			awsconfig.WithRegion(region),
		)
		if err != nil {
			c.logger.WithError(err).Error("failed to load base AWS config")
			return nil, fmt.Errorf("failed to load base AWS config: %v", err)
		}

		stsClient := sts.NewFromConfig(baseCfg)

		if sessionName == "" {
			sessionName = "BedrockGuardrailSession"
		}

		assumeRoleInput := &sts.AssumeRoleInput{
			RoleArn:         aws.String(roleARN),
			RoleSessionName: aws.String(sessionName),
		}

		assumeRoleOutput, err := stsClient.AssumeRole(ctx, assumeRoleInput)
		if err != nil {
			c.logger.WithError(err).Error("failed to assume role")
			return nil, fmt.Errorf("failed to assume role: %v", err)
		}

		awsCfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(
				func(ctx context.Context) (aws.Credentials, error) {
					return aws.Credentials{
						AccessKeyID:     *assumeRoleOutput.Credentials.AccessKeyId,
						SecretAccessKey: *assumeRoleOutput.Credentials.SecretAccessKey,
						SessionToken:    *assumeRoleOutput.Credentials.SessionToken,
					}, nil
				},
			)),
			awsconfig.WithRegion(region),
		)
		if err != nil {
			c.logger.WithError(err).Error("failed to load AWS config with assumed role")
			return nil, fmt.Errorf("failed to load AWS config with assumed role: %v", err)
		}
	} else {
		c.logger.Info("Using direct credentials for Bedrock client")
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(
				func(ctx context.Context) (aws.Credentials, error) {
					return aws.Credentials{
						AccessKeyID:     accessKey,
						SecretAccessKey: secretKey,
					}, nil
				},
			)),
			awsconfig.WithRegion(region),
		)
		if err != nil {
			c.logger.WithError(err).Error("failed to load AWS config")
			return nil, fmt.Errorf("failed to load AWS config: %v", err)
		}
	}

	c.client = bedrockruntime.NewFromConfig(awsCfg)
	return c, nil
}

func (c *client) ApplyGuardrail(
	ctx context.Context,
	params *bedrockruntime.ApplyGuardrailInput,
	optFns ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	if c.client == nil {
		return nil, fmt.Errorf("client not can be initialized")
	}
	return c.client.ApplyGuardrail(ctx, params, optFns...)
}
