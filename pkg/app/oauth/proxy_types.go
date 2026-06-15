package oauth

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

const CallbackPath = "/oauth/callback"

type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func oauthErr(code, desc string) *OAuthError { return &OAuthError{Code: code, Description: desc} }

type PendingAuthorization struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Scope               string `json:"scope"`
	IDPVerifier         string `json:"idp_verifier"`
	Resource            string `json:"resource,omitempty"`
	AuthID              string `json:"auth_id,omitempty"`
}

type CodeGrant struct {
	ClientID      string         `json:"client_id"`
	RedirectURI   string         `json:"redirect_uri"`
	CodeChallenge string         `json:"code_challenge"`
	Token         map[string]any `json:"token"`
}

type RegisteredGatewayClient struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name,omitempty"`
}

type FlowStore interface {
	SavePending(ctx context.Context, state string, p PendingAuthorization) error
	TakePending(ctx context.Context, state string) (*PendingAuthorization, error)
	SaveCode(ctx context.Context, code string, g CodeGrant) error
	TakeCode(ctx context.Context, code string) (*CodeGrant, error)
	SaveGatewayClient(ctx context.Context, c RegisteredGatewayClient) error
	GetGatewayClient(ctx context.Context, clientID string) (*RegisteredGatewayClient, error)
}

type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	RefreshToken string
	Resource     string
}

type ConsentChainer interface {
	ChainURL(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, principalSub, resumeURL string) (string, error)
}

type AuthProxy interface {
	Authorize(ctx context.Context, baseURL string, req AuthorizeRequest) (string, error)
	Callback(ctx context.Context, baseURL, state, code, idpErr, idpErrDesc string) (string, error)
	Exchange(ctx context.Context, baseURL string, req TokenRequest) (map[string]any, error)
}
