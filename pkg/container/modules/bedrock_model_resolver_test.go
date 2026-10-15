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

package modules

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/dig"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock/controlplane"
	controlplanemocks "github.com/NeuralTrust/TrustGate/pkg/infra/bedrock/controlplane/mocks"
)

// The resolver is built from the configuration and reaches the infra client
// through the port, with the credentials carried over field by field.
func TestBedrockModelResolver_IsWiredThroughThePort(t *testing.T) {
	client := controlplanemocks.NewClient(t)
	client.EXPECT().ResolveModelARN(mock.Anything, controlplane.Credentials{
		Region: "us-east-1", AccessKey: "ak", SecretKey: "sk", SessionToken: "st", UseRole: true, RoleARN: "role",
	}, "arn").Return("model-arn", nil).Once()

	c := dig.New()
	require.NoError(t, c.Provide(func() *config.Config { return &config.Config{} }))
	require.NoError(t, c.Provide(func() *slog.Logger { return slog.New(slog.DiscardHandler) }))
	require.NoError(t, c.Provide(func() controlplane.Client { return client }))
	require.NoError(t, c.Provide(newBedrockModelARNLookup))
	require.NoError(t, c.Provide(newBedrockModelResolver))

	require.NoError(t, c.Invoke(func(resolver appcatalog.BedrockModelResolver, lookup appcatalog.BedrockModelARNLookup) {
		require.NotNil(t, resolver)
		got, err := lookup.ResolveModelARN(context.Background(), appcatalog.BedrockCredentials{
			Region: "us-east-1", AccessKey: "ak", SecretKey: "sk", SessionToken: "st", UseRole: true, RoleARN: "role",
		}, "arn")
		require.NoError(t, err)
		assert.Equal(t, "model-arn", got)
		require.NoError(t, resolver.Close(context.Background()))
	}))
}
