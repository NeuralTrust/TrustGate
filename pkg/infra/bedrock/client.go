package bedrock

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Client --dir=. --output=../../../mocks --filename=bedrock_client_mock.go --case=underscore --with-expecter
type Client interface {
	ApplyGuardrail(
		ctx context.Context,
		params *bedrockruntime.ApplyGuardrailInput,
		optFns ...func(*bedrockruntime.Options),
	) (*bedrockruntime.ApplyGuardrailOutput, error)
	BuildClient(ctx context.Context, accessKey, secretKey, region string) (Client, error)
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

func (c *client) BuildClient(ctx context.Context, accessKey, secretKey, region string) (Client, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
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
	c.client = bedrockruntime.NewFromConfig(awsCfg)
	return c, nil
}

func (c *client) ApplyGuardrail(
	ctx context.Context,
	params *bedrockruntime.ApplyGuardrailInput,
	optFns ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	if c.client == nil {
		return nil, fmt.Errorf("client not initialized")
	}
	return c.client.ApplyGuardrail(ctx, params, optFns...)
}
