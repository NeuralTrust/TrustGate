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
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildRedisOptionsDefaultLoginIncludesACLUsername(t *testing.T) {
	options := buildRedisOptions(Config{
		Host:     "redis.example",
		Port:     6379,
		Username: "acl-user",
		Password: "secret",
	}, nil)

	require.Equal(t, "redis.example:6379", options.Addr)
	require.Equal(t, "acl-user", options.Username)
	require.Equal(t, "secret", options.Password)
	require.Nil(t, options.CredentialsProviderContext)
	require.Nil(t, options.TLSConfig)
}

func TestBuildRedisOptionsDefaultLoginEmptyUsername(t *testing.T) {
	options := buildRedisOptions(Config{
		Host:     "redis.example",
		Port:     6379,
		Password: "secret",
	}, nil)

	require.Empty(t, options.Username)
	require.Equal(t, "secret", options.Password)
}

func TestBuildRedisOptionsDefaultLoginTLS(t *testing.T) {
	options := buildRedisOptions(Config{
		Host:              "redis.example",
		Port:              6380,
		Username:          "acl-user",
		Password:          "secret",
		TLSEnabled:        true,
		TLSInsecureVerify: true,
	}, nil)

	require.NotNil(t, options.TLSConfig)
	require.True(t, options.TLSConfig.InsecureSkipVerify)
	require.Zero(t, options.TLSConfig.MinVersion)
}

func TestBuildRedisOptionsAWSLoginUsesIAMCredentialsProvider(t *testing.T) {
	provider := func(context.Context) (string, string, error) {
		return "iam-user", "sigv4-token", nil
	}
	options := buildRedisOptions(Config{
		Login:         "aws",
		Host:          "redis.example",
		Port:          6379,
		Username:      "iam-user",
		CacheName:     "cache.example",
		TLSEnabled:    true,
		AWSServerless: true,
	}, provider)

	require.Equal(t, "iam-user", options.Username)
	require.Empty(t, options.Password)
	require.NotNil(t, options.CredentialsProviderContext)
	require.Equal(t, uint16(tls.VersionTLS12), options.TLSConfig.MinVersion)

	user, token, err := options.CredentialsProviderContext(t.Context())
	require.NoError(t, err)
	require.Equal(t, "iam-user", user)
	require.Equal(t, "sigv4-token", token)
}
