package auth

import (
	"context"
	"errors"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

var ErrTokenAcquisition = errors.New("oauth2 client token acquisition failed")

type OAuth2ClientTokenSource interface {
	Token(ctx context.Context, cfg domain.OAuth2ClientConfig) (string, error)
}
