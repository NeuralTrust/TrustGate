package auth

import (
	"context"
	"crypto/x509"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
)

//go:generate mockery --name=JWTValidator --dir=. --output=./mocks --filename=auth_jwt_validator_mock.go --case=underscore --with-expecter
type JWTValidator interface {
	Validate(ctx context.Context, raw string, cfg *authdomain.OAuth2Config) (*identity.Principal, error)
}

//go:generate mockery --name=IntrospectionValidator --dir=. --output=./mocks --filename=auth_introspection_validator_mock.go --case=underscore --with-expecter
type IntrospectionValidator interface {
	Validate(ctx context.Context, raw string, cfg *authdomain.OAuth2Config) (*identity.Principal, error)
}

//go:generate mockery --name=MTLSValidator --dir=. --output=./mocks --filename=auth_mtls_validator_mock.go --case=underscore --with-expecter
type MTLSValidator interface {
	Validate(cert *x509.Certificate, cfg *authdomain.MTLSConfig) (*identity.Principal, error)
}

//go:generate mockery --name=ClientCertificateExtractor --dir=. --output=./mocks --filename=auth_client_certificate_extractor_mock.go --case=underscore --with-expecter
type ClientCertificateExtractor interface {
	FromXFCC(header string) (*x509.Certificate, error)
}
