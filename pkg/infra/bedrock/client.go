package bedrock

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/config"
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
}

type client struct {
	client *bedrockruntime.Client
}

func NewClient(cfg config.AWSConfig, logger *logrus.Logger) (Client, error) {
	var awsCfg aws.Config
	var err error
	ctx := context.Background()

	logger.Debug("using provided AWS credentials")

	awsCfg, err = awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     cfg.AccessKey,
					SecretAccessKey: cfg.SecretKey,
				}, nil
			},
		)),
		awsconfig.WithRegion(cfg.Region),
	)
	if err != nil {
		logger.WithError(err).Error("failed to load AWS config")
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	return &client{
		client: bedrockruntime.NewFromConfig(awsCfg),
	}, nil
}

func (c *client) GetClient() *bedrockruntime.Client {
	return c.client
}

func (c *client) ApplyGuardrail(
	ctx context.Context,
	params *bedrockruntime.ApplyGuardrailInput,
	optFns ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	return c.client.ApplyGuardrail(ctx, params, optFns...)
}
