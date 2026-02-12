package bedrock

import (
	"context"
	"fmt"
	"sync"

	bedrockClient "github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	pkgTypes "github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type client struct {
	clientPool    *sync.Map
	bedrockClient bedrockClient.Client
}

func NewBedrockClient() providers.Client {
	bedrockClientInstance := bedrockClient.NewClient()
	return &client{
		clientPool:    &sync.Map{},
		bedrockClient: bedrockClientInstance,
	}
}

// ---------------------------------------------------------------------------
// Completions (non-streaming) — sends reqBody raw to InvokeModel
// ---------------------------------------------------------------------------

func (c *client) Completions(
	ctx context.Context,
	cfg *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	model := c.resolveModel(reqBody, cfg.DefaultModel)
	if model == "" {
		return nil, fmt.Errorf("model is required")
	}

	bedrockCl, err := c.getOrCreateClient(ctx, cfg.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bedrock client: %w", err)
	}

	resp, err := bedrockCl.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(model),
		ContentType: aws.String("application/json"),
		Body:        reqBody,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to invoke model: %w", err)
	}

	return resp.Body, nil
}

// ---------------------------------------------------------------------------
// CompletionsStream — sends reqBody raw to InvokeModelWithResponseStream.
// Each chunk is forwarded as raw bytes (native provider format) so the
// adapter layer can decode and translate it when cross-provider.
// ---------------------------------------------------------------------------

func (c *client) CompletionsStream(
	reqCtx *pkgTypes.RequestContext,
	cfg *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	model := c.resolveModel(reqBody, cfg.DefaultModel)
	if model == "" {
		return fmt.Errorf("model is required")
	}

	bedrockCl, err := c.getOrCreateClient(reqCtx.C.Context(), cfg.Credentials)
	if err != nil {
		return fmt.Errorf("failed to create Bedrock client: %w", err)
	}

	resp, err := bedrockCl.InvokeModelWithResponseStream(reqCtx.C.Context(), &bedrockruntime.InvokeModelWithResponseStreamInput{
		ModelId:     aws.String(model),
		ContentType: aws.String("application/json"),
		Body:        reqBody,
	})
	if err != nil {
		return err
	}
	close(breakChan)

	for event := range resp.GetStream().Reader.Events() {
		switch v := event.(type) {
		case *types.ResponseStreamMemberChunk:
			if len(v.Value.Bytes) > 0 {
				streamChan <- v.Value.Bytes
			}
		default:
			// Ignore unknown event types.
		}
	}

	if err := resp.GetStream().Reader.Err(); err != nil {
		return fmt.Errorf("bedrock stream error: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// AWS client management
// ---------------------------------------------------------------------------

func (c *client) getOrCreateClient(ctx context.Context, credentials providers.Credentials) (*bedrockruntime.Client, error) {
	clientKey := buildClientKey(credentials)
	if clientVal, ok := c.clientPool.Load(clientKey); ok {
		cl, ok := clientVal.(*bedrockruntime.Client)
		if !ok {
			return nil, fmt.Errorf("invalid client type in pool")
		}
		return cl, nil
	}
	if c.bedrockClient == nil {
		cfg, err := buildAwsConfig(ctx, credentials)
		if err != nil {
			return nil, err
		}
		bedrockRuntimeClient := bedrockruntime.NewFromConfig(cfg)
		c.clientPool.Store(clientKey, bedrockRuntimeClient)
		return bedrockRuntimeClient, nil
	}

	if credentials.AwsBedrock == nil {
		return nil, fmt.Errorf("aws credentials are required")
	}

	bedrockClientInstance, err := c.bedrockClient.BuildClient(
		ctx,
		credentials.AwsBedrock.AccessKey,
		credentials.AwsBedrock.SecretKey,
		credentials.AwsBedrock.SessionToken,
		credentials.AwsBedrock.Region,
		credentials.AwsBedrock.UseRole,
		credentials.AwsBedrock.RoleARN,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build Bedrock client: %w", err)
	}
	runtimeClient := bedrockClientInstance.GetRuntimeClient()
	if runtimeClient == nil {
		return nil, fmt.Errorf("failed to get runtime client")
	}
	c.clientPool.Store(clientKey, runtimeClient)

	return runtimeClient, nil
}

func buildClientKey(credentials providers.Credentials) string {
	if credentials.AwsBedrock == nil {
		return credentials.ApiKey
	}
	return fmt.Sprintf("%s:%s:%s:%v:%s",
		credentials.ApiKey,
		credentials.AwsBedrock.AccessKey,
		credentials.AwsBedrock.Region,
		credentials.AwsBedrock.UseRole,
		credentials.AwsBedrock.RoleARN,
	)
}

func buildAwsConfig(ctx context.Context, credentials providers.Credentials) (aws.Config, error) {
	const defaultRegion = "us-east-1"

	if credentials.AwsBedrock == nil {
		return loadAWSConfig(ctx, credentials.ApiKey, credentials.ApiKey, "", defaultRegion)
	}

	region := credentials.AwsBedrock.Region
	if region == "" {
		region = defaultRegion
	}

	accessKey := credentials.AwsBedrock.AccessKey
	secretKey := credentials.AwsBedrock.SecretKey

	if credentials.AwsBedrock.UseRole && credentials.AwsBedrock.RoleARN != "" {
		creds, err := assumeRole(ctx, accessKey, secretKey, credentials.AwsBedrock.RoleARN, region)
		if err != nil {
			return aws.Config{}, err
		}
		return loadAWSConfig(ctx, *creds.AccessKeyId, *creds.SecretAccessKey, *creds.SessionToken, region)
	}

	return loadAWSConfig(ctx, accessKey, secretKey, "", region)
}

func loadAWSConfig(ctx context.Context, accessKey, secretKey, sessionToken, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     accessKey,
					SecretAccessKey: secretKey,
					SessionToken:    sessionToken,
				}, nil
			},
		)),
		config.WithRegion(region),
	)
}

func assumeRole(ctx context.Context, accessKey, secretKey, roleARN, region string, sessionName ...string) (*stsTypes.Credentials, error) {
	baseCfg, err := loadAWSConfig(ctx, accessKey, secretKey, "", region)
	if err != nil {
		return nil, fmt.Errorf("unable to load base AWS config: %w", err)
	}
	stsClient := sts.NewFromConfig(baseCfg)

	roleName := "BedrockClientSession"
	if len(sessionName) > 0 && sessionName[0] != "" {
		roleName = sessionName[0]
	}

	output, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to assume role: %w", err)
	}
	return output.Credentials, nil
}

// resolveModel extracts the model from the request body. Falls back to
// defaultModel when the body doesn't contain a "model" field.
func (c *client) resolveModel(reqBody []byte, defaultModel string) string {
	if m, err := adapter.ExtractModel(reqBody); err == nil && m != "" {
		return m
	}
	return defaultModel
}
