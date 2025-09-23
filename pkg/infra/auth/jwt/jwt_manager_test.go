package jwt

import (
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
	// Token signed with a different secret should be invalid
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
	// Set expiration in the past
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
	// Sign with different secret
	signed, err := signTokenWithSecret("wrong", &Claims{RegisteredClaims: jwtlib.RegisteredClaims{IssuedAt: jwtlib.NewNumericDate(time.Now())}})
	assert.NoError(t, err)

	mgr := newManagerWithSecret("right")
	claims, err := mgr.DecodeToken(signed)
	assert.Error(t, err)
	assert.Nil(t, claims)
}
