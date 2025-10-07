package bedrock

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

//go:generate mockery --name=Client --dir=. --output=../../../mocks --filename=bedrock_client_mock.go --case=underscore --with-expecter
type Client interface {
	ApplyGuardrail(
		ctx context.Context,
		params *bedrockruntime.ApplyGuardrailInput,
		optFns ...func(*bedrockruntime.Options),
	) (*bedrockruntime.ApplyGuardrailOutput, error)
	BuildClient(
		ctx context.Context,
		accessKey, secretKey, sessionToken, region string,
		useRole bool,
		roleARN, sessionName string,
	) (Client, error)
	GetRuntimeClient() *bedrockruntime.Client
}

type client struct {
	client     *bedrockruntime.Client
	clientPool *sync.Map
	muPool     *sync.Map
}

func NewClient() Client {
	return &client{
		clientPool: &sync.Map{},
		muPool:     &sync.Map{},
	}
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

func (c *client) GetRuntimeClient() *bedrockruntime.Client {
	return c.client
}

func (c *client) BuildClient(
	ctx context.Context,
	accessKey, secretKey, sessionToken, region string,
	useRole bool,
	roleARN, sessionName string,
) (Client, error) {
	clientKey := fmt.Sprintf("%s:%s:%s:%s:%v:%s:%s",
		accessKey, secretKey, sessionToken, region, useRole, roleARN, sessionName)

	if clientVal, ok := c.clientPool.Load(clientKey); ok {
		cl, ok := clientVal.(*client)
		if !ok {
			return nil, fmt.Errorf("invalid client type in pool")
		}
		return cl, nil
	}

	muIface, _ := c.muPool.LoadOrStore(clientKey, &sync.Mutex{})
	mu, ok := muIface.(*sync.Mutex)
	if !ok {
		return nil, fmt.Errorf("invalid mutex type in pool")
	}
	mu.Lock()
	defer mu.Unlock()
	defer c.muPool.Delete(clientKey)

	if clientVal, ok := c.clientPool.Load(clientKey); ok {
		cl, ok := clientVal.(*client)
		if !ok {
			return nil, fmt.Errorf("invalid client type in pool")
		}
		return cl, nil
	}

	var awsCfg aws.Config
	var err error

	if region == "" {
		region = "us-east-1"
	}

	if useRole && roleARN != "" {
		creds, err := assumeRole(ctx, accessKey, secretKey, roleARN, region, sessionName)
		if err != nil {
			return nil, fmt.Errorf("failed to assume role: %v", err)
		}

		awsCfg, err = loadAWSConfig(ctx, *creds.AccessKeyId, *creds.SecretAccessKey, *creds.SessionToken, region)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config with assumed role: %v", err)
		}
	} else {
		awsCfg, err = loadAWSConfig(ctx, accessKey, secretKey, sessionToken, region)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %v", err)
		}
	}

	newClient := &client{
		clientPool: c.clientPool,
		client:     bedrockruntime.NewFromConfig(awsCfg),
	}

	c.clientPool.Store(clientKey, newClient)

	return newClient, nil
}

func loadAWSConfig(ctx context.Context, accessKey, secretKey, sessionToken, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     accessKey,
					SecretAccessKey: secretKey,
					SessionToken:    sessionToken,
				}, nil
			},
		)),
		awsconfig.WithRegion(region),
	)
}

func assumeRole(ctx context.Context, accessKey, secretKey, roleARN, region, sessionName string) (*types.Credentials, error) {
	baseCfg, err := loadAWSConfig(ctx, accessKey, secretKey, "", region)
	if err != nil {
		return nil, fmt.Errorf("unable to load base AWS config: %w", err)
	}
	stsClient := sts.NewFromConfig(baseCfg)

	if sessionName == "" {
		sessionName = "BedrockClientSession"
	}

	output, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(sessionName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to assume role: %w", err)
	}
	return output.Credentials, nil
}
