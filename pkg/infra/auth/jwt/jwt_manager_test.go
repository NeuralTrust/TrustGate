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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
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
	assert.ErrorIs(t, err, ErrInvalidToken)
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
	assert.ErrorIs(t, err, ErrExpiredToken)
}

func signRawPayload(secret, header, payload string) string {
	enc := base64.RawURLEncoding
	input := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(payload))
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(input))
	return input + "." + enc.EncodeToString(h.Sum(nil))
}

func TestParse_ExpiryHandling(t *testing.T) {
	t.Parallel()
	const secret = "exp-secret"
	const hs256 = `{"alg":"HS256","typ":"JWT"}`
	soon := strconv.FormatInt(time.Now().Add(5*time.Minute).Unix(), 10)

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{name: "missing", token: signRawPayload(secret, hs256, `{"tenant_id":"t1"}`), wantErr: ErrInvalidToken},
		{name: "null", token: signRawPayload(secret, hs256, `{"tenant_id":"t1","exp":null}`), wantErr: ErrInvalidToken},
		{name: "non-numeric", token: signRawPayload(secret, hs256, `{"tenant_id":"t1","exp":"tomorrow"}`), wantErr: ErrInvalidToken},
		{name: "fractional", token: signRawPayload(secret, hs256, `{"tenant_id":"t1","exp":1.0}`), wantErr: ErrExpiredToken},
		{name: "exponent", token: signRawPayload(secret, hs256, `{"tenant_id":"t1","exp":1e3}`), wantErr: ErrExpiredToken},
		{name: "beyond max ttl", token: signRawPayload(secret, hs256, `{"tenant_id":"t1","exp":`+strconv.FormatInt(time.Now().Add(2*time.Hour).Unix(), 10)+`}`), wantErr: ErrInvalidToken},
		{name: "alg none", token: signRawPayload(secret, `{"alg":"none","typ":"JWT"}`, `{"tenant_id":"t1","exp":`+soon+`}`), wantErr: ErrInvalidToken},
		{name: "alg HS512 header", token: signRawPayload(secret, `{"alg":"HS512","typ":"JWT"}`, `{"tenant_id":"t1","exp":`+soon+`}`), wantErr: ErrInvalidToken},
		{name: "not yet valid", token: signRawPayload(secret, hs256, `{"tenant_id":"t1","exp":`+soon+`,"nbf":`+soon+`}`), wantErr: ErrInvalidToken},
		{name: "issued in the future", token: signRawPayload(secret, hs256, `{"tenant_id":"t1","exp":`+soon+`,"iat":`+soon+`}`), wantErr: ErrInvalidToken},
		{name: "within max ttl", token: signRawPayload(secret, hs256, `{"tenant_id":"t1","exp":`+soon+`}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mgr := newManagerWithSecret(secret)
			claims, err := mgr.DecodeToken(tt.token)
			if tt.wantErr == nil {
				assert.NoError(t, err)
				assert.NoError(t, mgr.ValidateToken(tt.token))
				assert.Equal(t, "t1", claims.TenantID)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr)
			assert.ErrorIs(t, mgr.ValidateToken(tt.token), tt.wantErr)
		})
	}
}

func TestValidateToken_ConfiguredMaxTTL(t *testing.T) {
	t.Parallel()
	claims := &Claims{RegisteredClaims: jwtlib.RegisteredClaims{
		ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(3 * time.Hour)),
	}}
	signed, err := signTokenWithSecret("ttl-secret", claims)
	assert.NoError(t, err)

	assert.ErrorIs(t, newManagerWithSecret("ttl-secret").ValidateToken(signed), ErrInvalidToken)

	longer := NewJwtManager(&config.ServerConfig{SecretKey: "ttl-secret", AdminTokenMaxTTL: 4 * time.Hour})
	assert.NoError(t, longer.ValidateToken(signed))
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
