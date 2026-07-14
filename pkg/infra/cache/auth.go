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

package cache

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

const (
	redisLoginAWS       = "aws"
	elastiCacheService  = "elasticache"
	authTokenTTLSeconds = 900
	emptyPayloadHash    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var errAWSRegionRequired = errors.New("aws region is required")

type awsConfigLoader func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error)

type redisTokenBuilder func(ctx context.Context, cacheName, region, user string, serverless bool, creds aws.CredentialsProvider) (string, error)

type credentialsProvider func(ctx context.Context) (username, password string, err error)

type redisAuthDependencies struct {
	loadConfig awsConfigLoader
	buildToken redisTokenBuilder
}

func defaultRedisAuthDependencies() redisAuthDependencies {
	return redisAuthDependencies{loadConfig: awsconfig.LoadDefaultConfig, buildToken: buildElastiCacheAuthToken}
}

func newCredentialsProvider(ctx context.Context, cfg *Config, deps redisAuthDependencies) (credentialsProvider, error) {
	if cfg.Login != redisLoginAWS {
		return nil, nil
	}
	awsConfig, err := deps.loadConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws redis authentication config: %w", err)
	}
	region := awsConfig.Region
	if region == "" {
		return nil, errAWSRegionRequired
	}
	creds := awsConfig.Credentials
	cacheName, user, serverless := cfg.CacheName, cfg.Username, cfg.AWSServerless
	buildToken := deps.buildToken
	return func(ctx context.Context) (string, string, error) {
		token, err := buildToken(ctx, cacheName, region, user, serverless, creds)
		if err != nil {
			return "", "", fmt.Errorf("build redis authentication token: %w", err)
		}
		return user, token, nil
	}, nil
}

func buildElastiCacheAuthToken(ctx context.Context, cacheName, region, user string, serverless bool, creds aws.CredentialsProvider) (string, error) {
	query := url.Values{}
	query.Set("Action", "connect")
	query.Set("User", user)
	query.Set("X-Amz-Expires", strconv.Itoa(authTokenTTLSeconds))
	if serverless {
		query.Set("ResourceType", "ServerlessCache")
	}
	endpoint := url.URL{Scheme: "https", Host: cacheName, Path: "/", RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create presign request: %w", err)
	}
	credentials, err := creds.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("retrieve aws credentials: %w", err)
	}
	signedURL, _, err := v4.NewSigner().PresignHTTP(ctx, credentials, req, emptyPayloadHash, elastiCacheService, region, time.Now())
	if err != nil {
		return "", fmt.Errorf("presign elasticache auth token: %w", err)
	}
	return strings.TrimPrefix(signedURL, "https://"), nil
}
