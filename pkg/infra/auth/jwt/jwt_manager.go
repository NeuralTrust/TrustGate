package jwt

import (
	"errors"
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
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrInvalidToken
			}
			return []byte(m.config.SecretKey), nil
		},
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return ErrExpiredToken
		}
		return ErrInvalidToken
	}

	if !token.Valid {
		return ErrInvalidToken
	}

	return nil
}

func (m *manager) DecodeToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(m.config.SecretKey), nil
		},
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
