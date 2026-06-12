package auth

import (
	"context"
	"crypto/x509"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
)

// Inbound credential validation ports. The auth-chain middleware drives
// them; the adapters live in infra/auth/{oidc,introspection,mtls}.

// JWTValidator validates a JWT against one Auth entry's OAuth2 config (JWKS).
//
//go:generate mockery --name=JWTValidator --dir=. --output=./mocks --filename=auth_jwt_validator_mock.go --case=underscore --with-expecter
type JWTValidator interface {
	Validate(ctx context.Context, raw string, cfg *authdomain.OAuth2Config) (*identity.Principal, error)
}

// IntrospectionValidator validates an opaque token via RFC 7662.
//
//go:generate mockery --name=IntrospectionValidator --dir=. --output=./mocks --filename=auth_introspection_validator_mock.go --case=underscore --with-expecter
type IntrospectionValidator interface {
	Validate(ctx context.Context, raw string, cfg *authdomain.OAuth2Config) (*identity.Principal, error)
}

// MTLSValidator validates a client certificate against one Auth entry's mTLS config.
//
//go:generate mockery --name=MTLSValidator --dir=. --output=./mocks --filename=auth_mtls_validator_mock.go --case=underscore --with-expecter
type MTLSValidator interface {
	Validate(cert *x509.Certificate, cfg *authdomain.MTLSConfig) (*identity.Principal, error)
}

// ClientCertificateExtractor parses the certificate an edge proxy forwarded
// in the X-Forwarded-Client-Cert header (XFCC format is adapter knowledge).
//
//go:generate mockery --name=ClientCertificateExtractor --dir=. --output=./mocks --filename=auth_client_certificate_extractor_mock.go --case=underscore --with-expecter
type ClientCertificateExtractor interface {
	FromXFCC(header string) (*x509.Certificate, error)
}
