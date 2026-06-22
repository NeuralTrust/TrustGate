// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"crypto/x509"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
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
