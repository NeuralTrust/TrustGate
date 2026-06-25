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

package bedrockguardrail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type awsCredentials struct {
	region          string
	useRole         bool
	roleARN         string
	sessionName     string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

func credentialsFromConfig(c Credentials) awsCredentials {
	return awsCredentials{
		region:          c.AWSRegion,
		useRole:         c.UseRole,
		roleARN:         c.RoleARN,
		sessionName:     c.SessionName,
		accessKeyID:     c.AccessKeyID,
		secretAccessKey: c.SecretAccessKey,
		sessionToken:    c.SessionToken,
	}
}

func (c awsCredentials) fingerprint() string {
	h := sha256.New()
	for _, field := range []string{
		c.region,
		strconv.FormatBool(c.useRole),
		c.roleARN,
		c.sessionName,
		c.accessKeyID,
		c.secretAccessKey,
		c.sessionToken,
	} {
		h.Write([]byte(field))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type guardrailClient interface {
	ApplyGuardrail(
		ctx context.Context,
		params *bedrockruntime.ApplyGuardrailInput,
		optFns ...func(*bedrockruntime.Options),
	) (*bedrockruntime.ApplyGuardrailOutput, error)
}

type cacheEntry struct {
	once   sync.Once
	client guardrailClient
	err    error
}

type clientCache struct {
	entries sync.Map
	build   func(ctx context.Context, creds awsCredentials) (guardrailClient, error)
}

func (c *clientCache) get(ctx context.Context, creds awsCredentials) (guardrailClient, error) {
	key := creds.fingerprint()
	for {
		v, _ := c.entries.LoadOrStore(key, &cacheEntry{})
		entry, ok := v.(*cacheEntry)
		if !ok {
			return nil, fmt.Errorf("bedrock_guardrail: invalid cache entry type")
		}
		entry.once.Do(func() {
			entry.client, entry.err = c.build(ctx, creds)
		})
		if entry.err == nil {
			return entry.client, nil
		}
		if c.entries.CompareAndDelete(key, v) {
			return nil, entry.err
		}
	}
}

type cachedGuardrailClient struct {
	cache *clientCache
}

func newCachedGuardrailClient() *cachedGuardrailClient {
	return &cachedGuardrailClient{
		cache: &clientCache{build: buildRuntimeClient},
	}
}

func (g *cachedGuardrailClient) ApplyGuardrail(
	ctx context.Context,
	creds awsCredentials,
	in *bedrockruntime.ApplyGuardrailInput,
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	client, err := g.cache.get(ctx, creds)
	if err != nil {
		return nil, err
	}
	return client.ApplyGuardrail(ctx, in)
}

func buildRuntimeClient(ctx context.Context, creds awsCredentials) (guardrailClient, error) {
	region := creds.region
	if region == "" {
		region = defaultRegion
	}

	staticProvider := credentials.NewStaticCredentialsProvider(
		creds.accessKeyID,
		creds.secretAccessKey,
		creds.sessionToken,
	)

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(staticProvider),
	)
	if err != nil {
		return nil, fmt.Errorf("bedrock_guardrail: load aws config: %w", err)
	}

	if creds.useRole && creds.roleARN != "" {
		sessionName := creds.sessionName
		if sessionName == "" {
			sessionName = defaultSessionName
		}
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, creds.roleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = sessionName
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	return bedrockruntime.NewFromConfig(cfg), nil
}
