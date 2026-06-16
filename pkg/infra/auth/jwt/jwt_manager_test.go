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

package jwt

import (
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func newManagerWithSecret(secret string) Manager {
	cfg := &config.ServerConfig{SecretKey: secret}
	return NewJwtManager(cfg)
}

func signTokenWithSecret(secret string, claims jwtlib.Claims) (string, error) {
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func TestCreateToken_AndValidate_Success(t *testing.T) {
	mgr := newManagerWithSecret("test-secret")

	token, err := mgr.CreateToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	err = mgr.ValidateToken(token)
	assert.NoError(t, err)
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	otherSecret := "other-secret"
	claims := &Claims{RegisteredClaims: jwtlib.RegisteredClaims{IssuedAt: jwtlib.NewNumericDate(time.Now())}}
	signed, err := signTokenWithSecret(otherSecret, claims)
	assert.NoError(t, err)

	mgr := newManagerWithSecret("test-secret")
	err = mgr.ValidateToken(signed)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestValidateToken_Expired(t *testing.T) {
	secret := "expire-secret"
	claims := &Claims{RegisteredClaims: jwtlib.RegisteredClaims{
		IssuedAt:  jwtlib.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(-1 * time.Hour)),
	}}
	signed, err := signTokenWithSecret(secret, claims)
	assert.NoError(t, err)

	mgr := newManagerWithSecret(secret)
	err = mgr.ValidateToken(signed)
	assert.Error(t, err)
	assert.Equal(t, ErrExpiredToken, err)
}

func TestValidateToken_NoExpClaim(t *testing.T) {
	secret := "no-exp-secret"
	claims := &Claims{RegisteredClaims: jwtlib.RegisteredClaims{
		IssuedAt: jwtlib.NewNumericDate(time.Now()),
	}}
	signed, err := signTokenWithSecret(secret, claims)
	assert.NoError(t, err)

	mgr := newManagerWithSecret(secret)
	err = mgr.ValidateToken(signed)
	assert.NoError(t, err)
}

func TestDecodeToken_Success(t *testing.T) {
	mgr := newManagerWithSecret("decode-secret")
	token, err := mgr.CreateToken()
	assert.NoError(t, err)

	claims, err := mgr.DecodeToken(token)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.NotNil(t, claims.IssuedAt)
}

func TestDecodeToken_Invalid(t *testing.T) {
	signed, err := signTokenWithSecret("wrong", &Claims{RegisteredClaims: jwtlib.RegisteredClaims{IssuedAt: jwtlib.NewNumericDate(time.Now())}})
	assert.NoError(t, err)

	mgr := newManagerWithSecret("right")
	claims, err := mgr.DecodeToken(signed)
	assert.Error(t, err)
	assert.Nil(t, claims)
}
