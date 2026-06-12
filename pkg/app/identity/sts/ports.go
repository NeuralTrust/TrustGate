package sts

import (
	"context"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenSigner mints TrustGate-issued JWTs and publishes the verification
// JWKS. The RSA implementation lives in infra; app code only depends on the
// signing contract.
//
//go:generate mockery --name=TokenSigner --dir=. --output=./mocks --filename=sts_token_signer_mock.go --case=underscore --with-expecter
type TokenSigner interface {
	Issuer() string
	// MintClaims signs the claims (RS256), stamping iss/iat/exp/jti.
	MintClaims(claims jwt.MapClaims, ttl time.Duration) (string, error)
	// JWKS is the published verification document for downstreams.
	JWKS() map[string]any
}

// IdPTokenClient posts a token-grant form to the IdP identified by issuer,
// resolving the token endpoint via OIDC discovery (cached). Implemented in
// infra; IdP OAuth errors surface as ErrInteractionRequired where the client
// must re-authenticate.
//
//go:generate mockery --name=IdPTokenClient --dir=. --output=./mocks --filename=sts_idp_token_client_mock.go --case=underscore --with-expecter
type IdPTokenClient interface {
	Call(ctx context.Context, issuer string, form url.Values) (*Token, error)
}
