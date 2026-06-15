package auth

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type Method string

const (
	MethodAPIKey     Method = "api_key"
	MethodOAuth2     Method = "oauth2"
	MethodIDP        Method = "idp"
	MethodPlayground Method = "playground"
)

type AuthContext struct {
	Method      Method
	GatewayID   ids.GatewayID
	GatewaySlug string
	ConsumerID  ids.ConsumerID
	AuthID      ids.AuthID
	Subject     string
	Claims      map[string]any
	Scopes      []string
	RoleIDs     []ids.RoleID
}

type authContextKey struct{}

func WithAuthContext(ctx context.Context, authCtx *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey{}, authCtx)
}

func AuthContextFromContext(ctx context.Context) (*AuthContext, bool) {
	authCtx, ok := ctx.Value(authContextKey{}).(*AuthContext)
	return authCtx, ok && authCtx != nil
}
