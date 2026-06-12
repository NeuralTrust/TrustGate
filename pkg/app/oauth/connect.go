package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/vault"
)

// The OAuth broker links third-party accounts (GitHub, Slack...) to a
// Principal through one-time consent, storing the tokens in the vault.
// Browsers cannot carry the inbound Bearer token, so the consent surface is
// authenticated by a short-lived single-purpose ticket minted during an
// authenticated MCP call (the elicitation URL).

var (
	ErrTicketNotFound   = errors.New("oauth connect: ticket expired or unknown")
	ErrProviderNotFound = errors.New("oauth connect: provider not configured for this consumer")
)

// ConnectTicket identifies the principal and virtual MCP a consent flow
// belongs to. It is the browser-side stand-in for the inbound credential.
type ConnectTicket struct {
	GatewayID    string `json:"gateway_id"`
	PrincipalSub string `json:"principal_sub"`
	ConsumerPath string `json:"consumer_path"`
	// ResumeURL, when set, is the parked client redirect (code + state) of an
	// inbound OAuth flow: the connect page offers a "Continue" action so the
	// user returns to their MCP client after linking providers.
	ResumeURL string `json:"resume_url,omitempty"`
}

// ConnectState parks one in-flight provider consent leg, keyed by the OAuth
// state sent to the third party. Verifier is the PKCE code_verifier minted
// at Start and redeemed at Callback.
type ConnectState struct {
	Ticket   ConnectTicket `json:"ticket"`
	TicketID string        `json:"ticket_id"`
	Provider string        `json:"provider"`
	Verifier string        `json:"verifier,omitempty"`
}

// ConnectStore persists tickets (reusable until expiry) and consent states
// (single-use) in Redis.
type ConnectStore interface {
	SaveTicket(ctx context.Context, id string, t ConnectTicket) error
	GetTicket(ctx context.Context, id string) (*ConnectTicket, error)
	SaveConnect(ctx context.Context, state string, s ConnectState) error
	TakeConnect(ctx context.Context, state string) (*ConnectState, error)
}

// ProviderStatus is one third-party provider on the connect page.
type ProviderStatus struct {
	Provider   string
	Registry   string
	Linked     bool
	AccountRef string
	ExpiresAt  time.Time
}

// ConnectPage is the data behind the consent UI.
type ConnectPage struct {
	ConsumerPath string
	Providers    []ProviderStatus
	// ResumeURL carries the parked client redirect during a chained consent
	// flow ("" otherwise).
	ResumeURL string
}

//go:generate mockery --name=ConnectService --dir=. --output=./mocks --filename=oauth_connect_service_mock.go --case=underscore --with-expecter
type ConnectService interface {
	// CreateTicket mints the consent ticket embedded in elicitation URLs.
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error)
	// Page resolves a ticket into the provider list with linked status.
	Page(ctx context.Context, ticketID string) (*ConnectPage, error)
	// Start begins the consent flow for one provider; returns the redirect URL.
	Start(ctx context.Context, baseURL, ticketID, provider string) (string, error)
	// Callback completes the consent flow and vaults the tokens. Returns the
	// ticket id so the UI can navigate back to the connect page.
	Callback(ctx context.Context, baseURL, provider, state, code, errCode, errDesc string) (string, error)
	// Disconnect revokes a linked account.
	Disconnect(ctx context.Context, ticketID, provider string) error
	// RefreshAuth returns the provider config usable for token refresh: the
	// manual config as-is, or the cached auto-registered client plus the
	// discovered endpoints. It never registers a new client.
	RefreshAuth(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error)
	// ChainURL implements ConsentChainer: connect-page URL when the principal
	// has unlinked forwarded providers behind the resource, "" otherwise.
	ChainURL(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, principalSub, resumeURL string) (string, error)
}

var _ ConnectService = (*connectService)(nil)

type connectService struct {
	store     ConnectStore
	vault     vaultdomain.Repository
	consumers appconsumer.DataFinder
	provider  ProviderClient
	registrar UpstreamRegistrar
}

func NewConnectService(
	store ConnectStore,
	vault vaultdomain.Repository,
	consumers appconsumer.DataFinder,
	provider ProviderClient,
	registrar UpstreamRegistrar,
) ConnectService {
	return &connectService{store: store, vault: vault, consumers: consumers, provider: provider, registrar: registrar}
}

func (s *connectService) CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error) {
	return s.mintTicket(ctx, ConnectTicket{
		GatewayID:    gatewayID.String(),
		PrincipalSub: principalSub,
		ConsumerPath: consumerPath,
	})
}

func (s *connectService) mintTicket(ctx context.Context, t ConnectTicket) (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := s.store.SaveTicket(ctx, id, t); err != nil {
		return "", err
	}
	return id, nil
}

// ChainURL is the chained-consent hook: called at the end of the inbound IdP
// leg, it mints a resume-carrying ticket and returns the connect page URL when
// the principal still has unlinked forwarded providers.
func (s *connectService) ChainURL(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, principalSub, resumeURL string) (string, error) {
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return "", err
	}
	rc := s.chainTarget(ctx, data, gatewayID, resource, principalSub)
	if rc == nil {
		return "", nil
	}
	id, err := s.mintTicket(ctx, ConnectTicket{
		GatewayID:    gatewayID.String(),
		PrincipalSub: principalSub,
		ConsumerPath: rc.Consumer.Path,
		ResumeURL:    resumeURL,
	})
	if err != nil {
		return "", err
	}
	return baseURL + rc.Consumer.Path + "/connect?ticket=" + id, nil
}

// chainTarget picks the consumer whose connect page should interrupt the
// inbound flow: the one addressed by the RFC 8707 resource when present,
// otherwise any MCP consumer with forwarded providers the principal has not
// linked yet (clients do not always send a resource indicator).
func (s *connectService) chainTarget(ctx context.Context, data *appconsumer.Data, gatewayID ids.GatewayID, resource, principalSub string) *appconsumer.RoutableConsumer {
	if resource != "" {
		if res, err := url.Parse(resource); err == nil && res.Path != "" {
			if rc, ok := data.MatchPath(res.Path); ok {
				if s.hasUnlinked(ctx, gatewayID, rc, principalSub) {
					return rc
				}
				return nil
			}
		}
	}
	for i := range data.Consumers {
		rc := &data.Consumers[i]
		if rc.Consumer == nil || !rc.Consumer.Active {
			continue
		}
		if s.hasUnlinked(ctx, gatewayID, rc, principalSub) {
			return rc
		}
	}
	return nil
}

func (s *connectService) hasUnlinked(ctx context.Context, gatewayID ids.GatewayID, rc *appconsumer.RoutableConsumer, principalSub string) bool {
	for _, reg := range rc.Registries {
		cfg := forwardedAuth(reg)
		if cfg == nil {
			continue
		}
		if _, err := s.vault.Find(ctx, gatewayID, principalSub, cfg.Provider); err != nil {
			return true
		}
	}
	return false
}

func (s *connectService) Page(ctx context.Context, ticketID string) (*ConnectPage, error) {
	ticket, gatewayID, rc, err := s.resolve(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	page := &ConnectPage{ConsumerPath: ticket.ConsumerPath, ResumeURL: ticket.ResumeURL}
	for _, reg := range rc.Registries {
		cfg := forwardedAuth(reg)
		if cfg == nil {
			continue
		}
		status := ProviderStatus{Provider: cfg.Provider, Registry: reg.Name}
		if cred, err := s.vault.Find(ctx, gatewayID, ticket.PrincipalSub, cfg.Provider); err == nil {
			status.Linked = true
			status.AccountRef = cred.AccountRef
			status.ExpiresAt = cred.ExpiresAt
		}
		page.Providers = append(page.Providers, status)
	}
	return page, nil
}

func (s *connectService) Start(ctx context.Context, baseURL, ticketID, provider string) (string, error) {
	ticket, gatewayID, rc, err := s.resolve(ctx, ticketID)
	if err != nil {
		return "", err
	}
	reg := providerRegistry(rc, provider)
	if reg == nil {
		return "", ErrProviderNotFound
	}
	cfg, err := s.effectiveAuth(ctx, baseURL, gatewayID, reg)
	if err != nil {
		return "", err
	}
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := s.store.SaveConnect(ctx, state, ConnectState{
		Ticket:   *ticket,
		TicketID: ticketID,
		Provider: provider,
		Verifier: verifier,
	}); err != nil {
		return "", err
	}
	return s.provider.AuthorizeURL(cfg, connectCallbackURL(baseURL, provider), state, s256(verifier)), nil
}

func (s *connectService) Callback(ctx context.Context, baseURL, provider, state, code, errCode, errDesc string) (string, error) {
	st, err := s.store.TakeConnect(ctx, state)
	if err != nil {
		return "", err
	}
	if st == nil || st.Provider != provider {
		return "", oauthErr("invalid_request", "unknown or expired state")
	}
	if errCode != "" {
		return st.TicketID, oauthErr(errCode, errDesc)
	}
	gatewayID, rc, err := s.routable(ctx, &st.Ticket)
	if err != nil {
		return st.TicketID, err
	}
	reg := providerRegistry(rc, provider)
	if reg == nil {
		return st.TicketID, ErrProviderNotFound
	}
	// Re-resolution is cache-hit only here: discovery and the DCR client
	// were materialized at Start, so no secrets travel through the state.
	cfg, err := s.effectiveAuth(ctx, baseURL, gatewayID, reg)
	if err != nil {
		return st.TicketID, err
	}
	token, err := s.provider.ExchangeCode(ctx, cfg, code, connectCallbackURL(baseURL, provider), st.Verifier)
	if err != nil {
		return st.TicketID, err
	}
	cred, err := vaultdomain.NewCredential(
		gatewayID, st.Ticket.PrincipalSub, provider, "",
		token.AccessToken, token.RefreshToken, token.Scopes, token.ExpiresAt,
	)
	if err != nil {
		return st.TicketID, err
	}
	if err := s.vault.Upsert(ctx, cred); err != nil {
		return st.TicketID, err
	}
	return st.TicketID, nil
}

// effectiveAuth resolves the OAuth client the gateway uses against the
// provider. Manual registration returns the admin-configured app; auto
// registration discovers the upstream's authorization server and registers
// (or reuses) a DCR client, defaulting scopes and the RFC 8707 resource from
// the upstream's metadata.
func (s *connectService) effectiveAuth(ctx context.Context, baseURL string, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto {
		return cfg, nil
	}
	meta, err := s.registrar.Discover(ctx, reg.MCPTarget.URL)
	if err != nil {
		return nil, err
	}
	client, err := s.registrar.EnsureClient(ctx, clientKey(gatewayID, reg), meta, connectCallbackURL(baseURL, cfg.Provider))
	if err != nil {
		return nil, err
	}
	return autoAuth(cfg, meta, client), nil
}

func (s *connectService) RefreshAuth(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto {
		return cfg, nil
	}
	meta, err := s.registrar.Discover(ctx, reg.MCPTarget.URL)
	if err != nil {
		return nil, err
	}
	client, err := s.registrar.CachedClient(ctx, clientKey(gatewayID, reg))
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("oauth connect: no registered client for provider %q; consent flow required", cfg.Provider)
	}
	return autoAuth(cfg, meta, client), nil
}

// autoAuth merges the registry config with discovered metadata and the
// registered client into the config the ProviderClient consumes.
func autoAuth(cfg *registrydomain.MCPAuth, meta *UpstreamAuthServer, client *RegisteredClient) *registrydomain.MCPAuth {
	out := *cfg
	out.ClientID = client.ClientID
	out.ClientSecret = client.ClientSecret
	out.AuthorizeURL = meta.AuthorizationEndpoint
	out.TokenURL = meta.TokenEndpoint
	if len(out.Scopes) == 0 {
		out.Scopes = meta.ScopesSupported
	}
	if out.Resource == "" {
		out.Resource = meta.Resource
	}
	return &out
}

func clientKey(gatewayID ids.GatewayID, reg *registrydomain.Registry) string {
	return gatewayID.String() + "|" + reg.ID.String()
}

func (s *connectService) Disconnect(ctx context.Context, ticketID, provider string) error {
	ticket, gatewayID, _, err := s.resolve(ctx, ticketID)
	if err != nil {
		return err
	}
	return s.vault.Delete(ctx, gatewayID, ticket.PrincipalSub, provider)
}

func (s *connectService) resolve(ctx context.Context, ticketID string) (*ConnectTicket, ids.GatewayID, *appconsumer.RoutableConsumer, error) {
	ticket, err := s.store.GetTicket(ctx, ticketID)
	if err != nil {
		return nil, ids.GatewayID{}, nil, err
	}
	if ticket == nil {
		return nil, ids.GatewayID{}, nil, ErrTicketNotFound
	}
	gatewayID, rc, err := s.routable(ctx, ticket)
	if err != nil {
		return nil, ids.GatewayID{}, nil, err
	}
	return ticket, gatewayID, rc, nil
}

func (s *connectService) routable(ctx context.Context, ticket *ConnectTicket) (ids.GatewayID, *appconsumer.RoutableConsumer, error) {
	gatewayID, err := ids.Parse[ids.GatewayKind](ticket.GatewayID)
	if err != nil {
		return ids.GatewayID{}, nil, fmt.Errorf("oauth connect: bad gateway id in ticket: %w", err)
	}
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return ids.GatewayID{}, nil, err
	}
	rc, ok := data.MatchPath(ticket.ConsumerPath)
	if !ok {
		return ids.GatewayID{}, nil, fmt.Errorf("oauth connect: consumer path %s no longer exists", ticket.ConsumerPath)
	}
	return gatewayID, rc, nil
}

func forwardedAuth(reg *registrydomain.Registry) *registrydomain.MCPAuth {
	if reg == nil || !reg.IsMCP() || reg.MCPTarget == nil || reg.MCPTarget.Auth == nil {
		return nil
	}
	if reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeForwarded {
		return nil
	}
	return reg.MCPTarget.Auth
}

func providerRegistry(rc *appconsumer.RoutableConsumer, provider string) *registrydomain.Registry {
	for _, reg := range rc.Registries {
		if cfg := forwardedAuth(reg); cfg != nil && cfg.Provider == provider {
			return reg
		}
	}
	return nil
}

func connectCallbackURL(baseURL, provider string) string {
	return baseURL + "/oauth/callback/" + provider
}
