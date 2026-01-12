package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
)

//go:generate mockery --name=Manager --dir=. --output=mocks/ --filename=jwt_manager_mock.go --case=underscore --with-expecter
type (
	Manager interface {
		CreateToken() (string, error)
		ValidateToken(tokenString string) error
		DecodeToken(tokenString string) (*Claims, error)
	}
	manager struct {
		config *config.ServerConfig
	}
)

func NewJwtManager(config *config.ServerConfig) Manager {
	return &manager{
		config: config,
	}
}

type Claims struct {
	TeamID    string `json:"team_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	jwt.RegisteredClaims
}

func (m *manager) CreateToken() (string, error) {
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(m.config.SecretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (m *manager) ValidateToken(tokenString string) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return ErrInvalidToken
	}

	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(m.config.SecretKey))
	h.Write([]byte(signingInput))
	expectedSig := h.Sum(nil)

	providedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrInvalidToken
	}

	if !hmac.Equal(expectedSig, providedSig) {
		return ErrInvalidToken
	}

	if exp, ok := m.extractExpiration(parts[1]); ok {
		if time.Now().After(exp) {
			return ErrExpiredToken
		}
	}

	return nil
}

func (m *manager) extractExpiration(payloadB64 string) (time.Time, bool) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return time.Time{}, false
	}

	var payload struct {
		Exp *json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return time.Time{}, false
	}

	if payload.Exp == nil {
		return time.Time{}, false
	}

	expInt, err := payload.Exp.Int64()
	if err != nil {
		return time.Time{}, false
	}

	return time.Unix(expInt, 0), true
}

func (m *manager) DecodeToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(m.config.SecretKey), nil
		},
		jwt.WithoutClaimsValidation(),
	)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
