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

package catalog_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	regmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock/controlplane"
	cpmocks "github.com/NeuralTrust/TrustGate/pkg/infra/bedrock/controlplane/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func bedrockRegistry(auth *registrydomain.TargetAuth) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](),
		LLMTarget: &registrydomain.LLMTarget{
			Provider: providers.ProviderBedrock,
			Auth:     auth,
		},
	}
}

func awsAuth() *registrydomain.TargetAuth {
	return &registrydomain.TargetAuth{
		Type: registrydomain.AuthTypeAWS,
		AWS: &registrydomain.AWSAuth{
			AccessKeyID:     "AKIAEXAMPLE",
			SecretAccessKey: "secret",
			Region:          "eu-west-1",
		},
	}
}

func catalogModels(slugs ...string) []catalogdomain.Model {
	out := make([]catalogdomain.Model, 0, len(slugs))
	for _, slug := range slugs {
		out = append(out, catalogdomain.Model{Slug: slug})
	}
	return out
}

func slugsOf(models []catalogdomain.Model) []string {
	out := make([]string, 0, len(models))
	for _, m := range models {
		out = append(out, m.Slug)
	}
	return out
}

func TestServerlessFilter_KeepsOnlyServerlessModels(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	client := cpmocks.NewClient(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(bedrockRegistry(awsAuth()), nil).Once()
	client.EXPECT().
		ListServerlessModelIDs(mock.Anything, mock.MatchedBy(func(c controlplane.Credentials) bool {
			return c.Region == "eu-west-1" && c.AccessKey == "AKIAEXAMPLE"
		})).
		Return(map[string]struct{}{
			"eu.anthropic.claude-sonnet-4-5-20250929-v1:0": {},
			"amazon.nova-pro-v1:0":                         {},
		}, nil).Once()

	filter := appcatalog.NewServerlessFilter(finder, client, discardLogger())
	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderBedrock,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models: catalogModels(
			"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
			"amazon.nova-pro-v1:0",
			"google.gemma-3-4b-it", // Bedrock Marketplace: needs an endpoint ARN.
			"us.anthropic.claude-sonnet-5",
		),
	})

	assert.Equal(t, []string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"amazon.nova-pro-v1:0",
	}, slugsOf(got))
}

func TestServerlessFilter_CachesPerCredentialSet(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	client := cpmocks.NewClient(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(bedrockRegistry(awsAuth()), nil).Twice()
	client.EXPECT().ListServerlessModelIDs(mock.Anything, mock.Anything).
		Return(map[string]struct{}{"amazon.nova-pro-v1:0": {}}, nil).Once()

	filter := appcatalog.NewServerlessFilter(finder, client, discardLogger())
	in := appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderBedrock,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models:       catalogModels("amazon.nova-pro-v1:0", "google.gemma-3-4b-it"),
	}

	for range 2 {
		got := filter.Filter(context.Background(), in)
		assert.Equal(t, []string{"amazon.nova-pro-v1:0"}, slugsOf(got))
	}
}

func TestServerlessFilter_PassesThroughNonBedrockProvider(t *testing.T) {
	t.Parallel()
	// Neither collaborator may be touched: mockery fails the test on any call.
	filter := appcatalog.NewServerlessFilter(
		regmocks.NewFinder(t), cpmocks.NewClient(t), discardLogger(),
	)
	models := catalogModels("gpt-4o", "gpt-4o-mini")

	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderOpenAI,
		GatewayID:    ids.New[ids.GatewayKind](),
		RegistryID:   ids.New[ids.RegistryKind](),
		Models:       models,
	})

	assert.Equal(t, models, got)
}

func TestServerlessFilter_FallsBackWhenLookupFails(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	client := cpmocks.NewClient(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(bedrockRegistry(awsAuth()), nil).Once()
	client.EXPECT().ListServerlessModelIDs(mock.Anything, mock.Anything).
		Return(nil, errors.New("403 AccessDeniedException")).Once()

	filter := appcatalog.NewServerlessFilter(finder, client, discardLogger())
	models := catalogModels("amazon.nova-pro-v1:0", "google.gemma-3-4b-it")

	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderBedrock,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models:       models,
	})

	assert.Equal(t, models, got, "an unreachable control plane must not empty the picker")
}

func TestServerlessFilter_FallsBackWhenNothingOverlaps(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	client := cpmocks.NewClient(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(bedrockRegistry(awsAuth()), nil).Once()
	client.EXPECT().ListServerlessModelIDs(mock.Anything, mock.Anything).
		Return(map[string]struct{}{"something.else-v1:0": {}}, nil).Once()

	filter := appcatalog.NewServerlessFilter(finder, client, discardLogger())
	models := catalogModels("amazon.nova-pro-v1:0")

	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderBedrock,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models:       models,
	})

	assert.Equal(t, models, got)
}

func TestServerlessFilter_SkipsWithoutAWSCredentials(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	client := cpmocks.NewClient(t)
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	finder.EXPECT().FindByID(mock.Anything, gatewayID, registryID).
		Return(bedrockRegistry(nil), nil).Once()

	filter := appcatalog.NewServerlessFilter(finder, client, discardLogger())
	models := catalogModels("amazon.nova-pro-v1:0")

	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderBedrock,
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models:       models,
	})

	assert.Equal(t, models, got)
}

func TestServerlessFilter_SkipsWithoutRegistryID(t *testing.T) {
	t.Parallel()
	filter := appcatalog.NewServerlessFilter(
		regmocks.NewFinder(t), cpmocks.NewClient(t), discardLogger(),
	)
	models := catalogModels("amazon.nova-pro-v1:0")

	got := filter.Filter(context.Background(), appcatalog.ServerlessFilterInput{
		ProviderCode: providers.ProviderBedrock,
		Models:       models,
	})

	assert.Equal(t, models, got)
}
