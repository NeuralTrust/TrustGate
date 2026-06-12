package registry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	regmocks "github.com/NeuralTrust/AgentGateway/pkg/app/registry/mocks"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	locatormocks "github.com/NeuralTrust/AgentGateway/pkg/infra/providers/factory/mocks"
	providermocks "github.com/NeuralTrust/AgentGateway/pkg/infra/providers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestConnectionTester_Inline_OK(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := locatormocks.NewProviderLocator(t)
	probe := providermocks.NewConnectionTester(t)

	probe.EXPECT().
		TestConnection(mock.Anything, mock.MatchedBy(func(cfg *providers.Config) bool {
			return cfg.Credentials.ApiKey == "sk-1"
		})).
		Return(providers.ProbeResult{OK: true, Stage: providers.StageAuthentication, StatusCode: 200}).
		Once()
	locator.EXPECT().Get("openai").Return(nil, nil).Once()
	locator.EXPECT().GetTester("openai").Return(probe, nil).Once()

	svc := appregistry.NewConnectionTester(finder, locator, newTestLogger())
	res, err := svc.Test(context.Background(), appregistry.TestConnectionInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Provider:  "openai",
		Auth:      domain.NewAPIKeyAuth("sk-1"),
	})

	require.NoError(t, err)
	assert.True(t, res.OK)
	assert.Equal(t, "authentication", res.Stage)
	assert.Equal(t, "openai", res.Provider)
	assert.Equal(t, 200, res.StatusCode)
	assert.GreaterOrEqual(t, res.LatencyMs, int64(0))
}

func TestConnectionTester_ByID_ResolvesAndProbes(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := locatormocks.NewProviderLocator(t)
	probe := providermocks.NewConnectionTester(t)

	gwID := ids.New[ids.GatewayKind]()
	regID := ids.New[ids.RegistryKind]()
	reg := domain.Rehydrate(domain.RehydrateParams{
		ID:        regID,
		GatewayID: gwID,
		Name:      "anthropic-backend",
		LLMTarget: &domain.LLMTarget{
			Provider: "anthropic",
			Auth:     domain.NewAPIKeyAuth("sk-anthropic"),
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	finder.EXPECT().FindByID(mock.Anything, gwID, regID).Return(reg, nil).Once()
	locator.EXPECT().Get("anthropic").Return(nil, nil).Once()
	locator.EXPECT().GetTester("anthropic").Return(probe, nil).Once()
	probe.EXPECT().
		TestConnection(mock.Anything, mock.Anything).
		Return(providers.ProbeResult{OK: false, Stage: providers.StageAuthentication, StatusCode: 401, Message: "rejected"}).
		Once()

	svc := appregistry.NewConnectionTester(finder, locator, newTestLogger())
	res, err := svc.Test(context.Background(), appregistry.TestConnectionInput{
		GatewayID:  gwID,
		RegistryID: &regID,
	})

	require.NoError(t, err)
	assert.False(t, res.OK)
	assert.Equal(t, "authentication", res.Stage)
	assert.Equal(t, "anthropic", res.Provider)
	assert.Equal(t, 401, res.StatusCode)
}

func TestConnectionTester_ByID_NotFound(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := locatormocks.NewProviderLocator(t)

	gwID := ids.New[ids.GatewayKind]()
	regID := ids.New[ids.RegistryKind]()
	finder.EXPECT().FindByID(mock.Anything, gwID, regID).Return(nil, domain.ErrNotFound).Once()

	svc := appregistry.NewConnectionTester(finder, locator, newTestLogger())
	_, err := svc.Test(context.Background(), appregistry.TestConnectionInput{
		GatewayID:  gwID,
		RegistryID: &regID,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestConnectionTester_UnsupportedAuthType(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := locatormocks.NewProviderLocator(t)

	svc := appregistry.NewConnectionTester(finder, locator, newTestLogger())
	res, err := svc.Test(context.Background(), appregistry.TestConnectionInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Provider:  "vertex",
		Auth:      domain.NewOAuth2Auth(&domain.TargetOAuthConfig{TokenURL: "https://x", GrantType: "client_credentials"}),
	})

	require.NoError(t, err)
	assert.False(t, res.OK)
	assert.Equal(t, "unsupported", res.Stage)
}

func TestConnectionTester_AzureModesAreSupported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		auth *domain.TargetAuth
		want providers.Azure
		key  string
	}{
		{
			name: "api key",
			auth: &domain.TargetAuth{
				Type:  domain.AuthTypeAzure,
				Azure: &domain.AzureAuth{Endpoint: "https://example.openai.azure.com", APIKey: "azure-key"},
			},
			want: providers.Azure{
				Endpoint: "https://example.openai.azure.com",
				AuthMode: providers.AzureAuthModeAPIKey,
			},
			key: "azure-key",
		},
		{
			name: "service principal",
			auth: &domain.TargetAuth{
				Type: domain.AuthTypeAzure,
				Azure: &domain.AzureAuth{
					Endpoint:     "https://example.openai.azure.com",
					TenantID:     "tenant",
					ClientID:     "client",
					ClientSecret: "secret",
				},
			},
			want: providers.Azure{
				Endpoint:     "https://example.openai.azure.com",
				AuthMode:     providers.AzureAuthModeServicePrincipal,
				TenantID:     "tenant",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		{
			name: "default azure credential",
			auth: &domain.TargetAuth{
				Type:  domain.AuthTypeAzure,
				Azure: &domain.AzureAuth{Endpoint: "https://example.openai.azure.com", UseManagedIdentity: true},
			},
			want: providers.Azure{
				Endpoint:    "https://example.openai.azure.com",
				AuthMode:    providers.AzureAuthModeDefaultAzureCredential,
				UseIdentity: true,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			finder := regmocks.NewFinder(t)
			locator := locatormocks.NewProviderLocator(t)
			probe := providermocks.NewConnectionTester(t)

			probe.EXPECT().
				TestConnection(mock.Anything, mock.MatchedBy(func(cfg *providers.Config) bool {
					if cfg.Credentials.ApiKey != tt.key || cfg.Credentials.Azure == nil {
						return false
					}
					return *cfg.Credentials.Azure == tt.want
				})).
				Return(providers.ProbeResult{OK: true, Stage: providers.StageAuthentication, StatusCode: 200}).
				Once()
			locator.EXPECT().Get("azure").Return(nil, nil).Once()
			locator.EXPECT().GetTester("azure").Return(probe, nil).Once()

			svc := appregistry.NewConnectionTester(finder, locator, newTestLogger())
			res, err := svc.Test(context.Background(), appregistry.TestConnectionInput{
				GatewayID: ids.New[ids.GatewayKind](),
				Provider:  "azure",
				Auth:      tt.auth,
			})

			require.NoError(t, err)
			assert.True(t, res.OK)
			assert.Equal(t, "authentication", res.Stage)
			assert.Equal(t, "azure", res.Provider)
		})
	}
}

func TestConnectionTester_UnsupportedProvider(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := locatormocks.NewProviderLocator(t)

	locator.EXPECT().Get("vertex").Return(nil, nil).Once()
	locator.EXPECT().GetTester("vertex").Return(nil, errors.New("does not support connection testing")).Once()

	svc := appregistry.NewConnectionTester(finder, locator, newTestLogger())
	res, err := svc.Test(context.Background(), appregistry.TestConnectionInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Provider:  "vertex",
		Auth:      domain.NewAPIKeyAuth("token"),
	})

	require.NoError(t, err)
	assert.False(t, res.OK)
	assert.Equal(t, "unsupported", res.Stage)
	assert.Equal(t, "vertex", res.Provider)
}

func TestConnectionTester_InvalidProvider(t *testing.T) {
	t.Parallel()
	finder := regmocks.NewFinder(t)
	locator := locatormocks.NewProviderLocator(t)

	locator.EXPECT().Get("foobar").Return(nil, errors.New("unsupported provider: foobar")).Once()

	svc := appregistry.NewConnectionTester(finder, locator, newTestLogger())
	_, err := svc.Test(context.Background(), appregistry.TestConnectionInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Provider:  "foobar",
		Auth:      domain.NewAPIKeyAuth("token"),
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, commonerrors.ErrValidation)
}
