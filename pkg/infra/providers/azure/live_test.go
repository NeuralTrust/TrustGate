//go:build azure_live

package azure

import (
	"context"
	"os"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

func TestLiveAzureConnection_ServicePrincipal(t *testing.T) {
	endpoint := os.Getenv("AZURE_OPENAI_ENDPOINT")
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if endpoint == "" || tenantID == "" || clientID == "" || clientSecret == "" {
		t.Skip("AZURE_OPENAI_ENDPOINT, AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are required")
	}

	c := &client{
		pool:        providers.NewHTTPClientPool(),
		tokenSource: getAzureBearerToken,
	}
	result := c.TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{
			Azure: &providers.Azure{
				Endpoint:     endpoint,
				AuthMode:     providers.AzureAuthModeServicePrincipal,
				TenantID:     tenantID,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			},
		},
	})
	if !result.OK {
		t.Fatalf("TestConnection failed: stage=%s status=%d message=%s", result.Stage, result.StatusCode, result.Message)
	}
}

func TestLiveAzureConnection_DefaultAzureCredential(t *testing.T) {
	endpoint := os.Getenv("AZURE_OPENAI_ENDPOINT")
	if endpoint == "" {
		t.Skip("AZURE_OPENAI_ENDPOINT is required")
	}
	if os.Getenv("AZURE_LIVE_DEFAULT_CREDENTIAL") != "1" {
		t.Skip("AZURE_LIVE_DEFAULT_CREDENTIAL=1 is required")
	}

	c := &client{
		pool:        providers.NewHTTPClientPool(),
		tokenSource: getAzureBearerToken,
	}
	result := c.TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{
			Azure: &providers.Azure{
				Endpoint:    endpoint,
				AuthMode:    providers.AzureAuthModeDefaultAzureCredential,
				UseIdentity: true,
			},
		},
	})
	if !result.OK {
		t.Fatalf("TestConnection failed: stage=%s status=%d message=%s", result.Stage, result.StatusCode, result.Message)
	}
}
