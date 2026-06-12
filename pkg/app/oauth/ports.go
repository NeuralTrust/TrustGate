package oauth

import (
	"context"
	"errors"
	"time"

	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

// ProviderToken is a third-party token response (GitHub, Slack, Linear...).
type ProviderToken struct {
	AccessToken  string
	RefreshToken string
	Scopes       []string
	ExpiresAt    time.Time
}

// ProviderClient runs the OAuth authorization-code legs against a third-party
// provider configured on a forwarded-mode MCP target. The gateway is the
// OAuth client; the agent never sees these credentials. Implemented in infra.
//
//go:generate mockery --name=ProviderClient --dir=. --output=./mocks --filename=oauth_provider_client_mock.go --case=underscore --with-expecter
type ProviderClient interface {
	// AuthorizeURL builds the provider consent URL. challenge enables PKCE
	// (S256); cfg.Resource adds the RFC 8707 resource indicator.
	AuthorizeURL(cfg *registrydomain.MCPAuth, redirectURI, state, challenge string) string
	// ExchangeCode redeems the authorization code at the provider token
	// endpoint. Public clients (DCR, no secret) authenticate with PKCE only.
	ExchangeCode(ctx context.Context, cfg *registrydomain.MCPAuth, code, redirectURI, verifier string) (*ProviderToken, error)
	// Refresh trades the refresh token for a fresh access token.
	Refresh(ctx context.Context, cfg *registrydomain.MCPAuth, refreshToken string) (*ProviderToken, error)
}

// ErrUpstreamNotDiscoverable: the upstream does not publish MCP authorization
// metadata; the admin must fall back to manual registration.
var ErrUpstreamNotDiscoverable = errors.New(
	"oauth dcr: upstream does not publish OAuth protected-resource metadata; configure registration: manual with a pre-registered OAuth app")

// UpstreamAuthServer is the discovered authorization-server surface of one
// upstream MCP server.
type UpstreamAuthServer struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
	Resource              string   `json:"resource"`
}

// RegisteredClient is the gateway's DCR-issued client at one upstream.
type RegisteredClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURI  string `json:"redirect_uri"`
}

// ClientStore persists DCR registrations (no TTL: re-registering is cheap but
// churns the upstream's client table).
type ClientStore interface {
	SaveClient(ctx context.Context, key string, c RegisteredClient) error
	GetClient(ctx context.Context, key string) (*RegisteredClient, error)
}

// UpstreamRegistrar discovers upstream authorization servers (RFC 9728 +
// RFC 8414) and maintains the gateway's dynamically registered clients
// (RFC 7591). Implemented in infra.
//
//go:generate mockery --name=UpstreamRegistrar --dir=. --output=./mocks --filename=oauth_upstream_registrar_mock.go --case=underscore --with-expecter
type UpstreamRegistrar interface {
	// Discover resolves the upstream MCP URL to its authorization-server
	// metadata.
	Discover(ctx context.Context, upstreamURL string) (*UpstreamAuthServer, error)
	// EnsureClient returns the gateway's registered client at the upstream,
	// registering on first use. Key scopes the registration per
	// (gateway, registry) so tenants never share a client identity.
	EnsureClient(ctx context.Context, key string, meta *UpstreamAuthServer, redirectURI string) (*RegisteredClient, error)
	// CachedClient returns the stored registration without registering (used
	// by the refresh path, which must not mint new registrations).
	CachedClient(ctx context.Context, key string) (*RegisteredClient, error)
}
