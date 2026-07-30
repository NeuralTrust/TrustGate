// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bedrock

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Refresh STS / IRSA credentials before the Absolute expiry so long-lived
// pooled Bedrock clients keep working across credential rotation.
const credentialsExpiryWindow = 5 * time.Minute

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=bedrock_client_mock.go --case=underscore --with-expecter
type Client interface {
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

	if region == "" {
		region = "us-east-1"
	}

	awsCfg, err := loadAWSConfig(ctx, accessKey, secretKey, sessionToken, region)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	if useRole && roleARN != "" {
		if sessionName == "" {
			sessionName = "BedrockClientSession"
		}
		// AssumeRoleProvider re-calls STS when the CredentialsCache marks
		// creds expired. Base identity (IRSA or static keys) also refreshes
		// via the chain held by the STS client — do not bake one-shot
		// temporary keys into a static provider.
		stsClient := sts.NewFromConfig(awsCfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = sessionName
		})
		awsCfg.Credentials = aws.NewCredentialsCache(provider, func(o *aws.CredentialsCacheOptions) {
			o.ExpiryWindow = credentialsExpiryWindow
		})
	}

	newClient := &client{
		clientPool: c.clientPool,
		client:     bedrockruntime.NewFromConfig(awsCfg),
	}

	c.clientPool.Store(clientKey, newClient)

	return newClient, nil
}

// loadAWSConfig builds an AWS config. When access keys are set, they are used
// as static credentials. When omitted, the default credential chain is used
// (IRSA on EKS, env vars, instance profile, etc.).
func loadAWSConfig(ctx context.Context, accessKey, secretKey, sessionToken, region string) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}
	if accessKey != "" && secretKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken),
		))
	}
	return awsconfig.LoadDefaultConfig(ctx, opts...)
}
