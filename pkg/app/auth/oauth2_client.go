package auth

import (
	"context"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

type OAuth2ClientTokenSource interface {
	Token(ctx context.Context, cfg domain.OAuth2ClientConfig) (string, error)
}
