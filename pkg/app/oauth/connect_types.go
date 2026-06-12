package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

var (
	ErrTicketNotFound   = errors.New("oauth connect: ticket expired or unknown")
	ErrProviderNotFound = errors.New("oauth connect: provider not configured for this consumer")
)

type ConnectTicket struct {
	GatewayID    string `json:"gateway_id"`
	PrincipalSub string `json:"principal_sub"`
	ConsumerPath string `json:"consumer_path"`
	ResumeURL    string `json:"resume_url,omitempty"`
}

type ConnectState struct {
	Ticket   ConnectTicket `json:"ticket"`
	TicketID string        `json:"ticket_id"`
	Provider string        `json:"provider"`
	Verifier string        `json:"verifier,omitempty"`
}

type ConnectStore interface {
	SaveTicket(ctx context.Context, id string, t ConnectTicket) error
	GetTicket(ctx context.Context, id string) (*ConnectTicket, error)
	SaveConnect(ctx context.Context, state string, s ConnectState) error
	TakeConnect(ctx context.Context, state string) (*ConnectState, error)
}

type ProviderStatus struct {
	Provider   string
	Registry   string
	Linked     bool
	AccountRef string
	ExpiresAt  time.Time
}

type ConnectPage struct {
	ConsumerPath string
	Providers    []ProviderStatus
	ResumeURL    string
}

//go:generate mockery --name=ConnectService --dir=. --output=./mocks --filename=oauth_connect_service_mock.go --case=underscore --with-expecter
type ConnectService interface {
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error)
	Page(ctx context.Context, ticketID string) (*ConnectPage, error)
	Start(ctx context.Context, baseURL, ticketID, provider string) (string, error)
	Callback(ctx context.Context, baseURL, provider, state, code, errCode, errDesc string) (string, error)
	Disconnect(ctx context.Context, ticketID, provider string) error
	RefreshAuth(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error)
	ChainURL(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, principalSub, resumeURL string) (string, error)
}
