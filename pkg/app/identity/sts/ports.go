package sts

import (
	"context"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//go:generate mockery --name=TokenSigner --dir=. --output=./mocks --filename=sts_token_signer_mock.go --case=underscore --with-expecter
type TokenSigner interface {
	Issuer() string
	MintClaims(claims jwt.MapClaims, ttl time.Duration) (string, error)
	JWKS() map[string]any
}

//go:generate mockery --name=IdPTokenClient --dir=. --output=./mocks --filename=sts_idp_token_client_mock.go --case=underscore --with-expecter
type IdPTokenClient interface {
	Call(ctx context.Context, issuer string, form url.Values) (*Token, error)
}
