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
