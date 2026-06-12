package oauth

import (
	"context"
	"errors"
	"time"

	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type ProviderToken struct {
	AccessToken  string
	RefreshToken string
	Scopes       []string
	ExpiresAt    time.Time
}

//go:generate mockery --name=ProviderClient --dir=. --output=./mocks --filename=oauth_provider_client_mock.go --case=underscore --with-expecter
type ProviderClient interface {
	AuthorizeURL(cfg *registrydomain.MCPAuth, redirectURI, state, challenge string) string
	ExchangeCode(ctx context.Context, cfg *registrydomain.MCPAuth, code, redirectURI, verifier string) (*ProviderToken, error)
	Refresh(ctx context.Context, cfg *registrydomain.MCPAuth, refreshToken string) (*ProviderToken, error)
}

var ErrUpstreamNotDiscoverable = errors.New(
	"oauth dcr: upstream does not publish OAuth protected-resource metadata; configure registration: manual with a pre-registered OAuth app")

// ErrInvalidGrant marks a definitive token rejection by the provider
// (revoked/expired grant). Callers should re-run consent; any other refresh
// failure is transient and must not invalidate the stored grant.
var ErrInvalidGrant = errors.New("oauth provider: grant is no longer valid")

type UpstreamAuthServer struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
	Resource              string   `json:"resource"`
}

type RegisteredClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURI  string `json:"redirect_uri"`
}

type ClientStore interface {
	SaveClient(ctx context.Context, key string, c RegisteredClient) error
	GetClient(ctx context.Context, key string) (*RegisteredClient, error)
}

//go:generate mockery --name=UpstreamRegistrar --dir=. --output=./mocks --filename=oauth_upstream_registrar_mock.go --case=underscore --with-expecter
type UpstreamRegistrar interface {
	Discover(ctx context.Context, upstreamURL string) (*UpstreamAuthServer, error)
	EnsureClient(ctx context.Context, key string, meta *UpstreamAuthServer, redirectURI string) (*RegisteredClient, error)
	CachedClient(ctx context.Context, key string) (*RegisteredClient, error)
}
