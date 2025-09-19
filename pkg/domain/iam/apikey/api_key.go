package apikey

import (
	"errors"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database/types"
	"github.com/google/uuid"
)

type SubjectType string

const (
	PolicyType  SubjectType = "policy"
	GatewayType SubjectType = "gateway"
)

func SubjectFromString(value string) (SubjectType, error) {
	switch value {
	case string(PolicyType):
		return PolicyType, nil
	case string(GatewayType):
		return GatewayType, nil
	default:
		return "", ErrInvalidSubjectType
	}
}

var (
	ErrInvalidName        = errors.New("iam api key name cannot be empty")
	ErrInvalidExpiresAt   = errors.New("iam api key expires_at cannot be zero")
	ErrExpiresAtInPast    = errors.New("iam api key expires_at cannot be in the past")
	ErrSubjectRequired    = errors.New("iam api key subject is required")
	ErrInvalidSubjectType = errors.New("invalid subject type: must be 'policy' or 'gateway'")
)

type APIKey struct {
	ID          uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey"`
	Key         string          `json:"key" gorm:"index"`
	Name        string          `json:"name"`
	Active      bool            `json:"active"`
	SubjectType SubjectType     `json:"subject_type" gorm:"not null"`
	Subject     *uuid.UUID      `json:"subject,omitempty" gorm:"type:uuid;index"`
	Policies    types.UUIDArray `json:"policies,omitempty" gorm:"type:uuid[]"`
	ExpiresAt   *time.Time      `json:"expires_at"`
	CreatedAt   time.Time       `json:"created_at"`
}

func NewIAMApiKey(
	ID uuid.UUID,
	name string,
	key string,
	subjectType SubjectType,
	subject *uuid.UUID,
	policies types.UUIDArray,
	expiresAt *time.Time,

) (*APIKey, error) {
	apiKey := &APIKey{
		ID:          ID,
		Name:        name,
		Key:         key,
		Active:      true,
		SubjectType: subjectType,
		Subject:     subject,
		ExpiresAt:   expiresAt,
		Policies:    policies,
	}

	if err := apiKey.Validate(); err != nil {
		return nil, err
	}

	return apiKey, nil
}

func (a APIKey) Validate() error {
	if a.Name == "" {
		return ErrInvalidName
	}

	if a.ExpiresAt.IsZero() {
		return ErrInvalidExpiresAt
	}

	if a.ExpiresAt.Before(time.Now()) {
		return ErrExpiresAtInPast
	}

	if a.SubjectType == GatewayType && a.Subject == nil {
		return ErrSubjectRequired
	}

	return nil
}

func (a APIKey) IsValid() bool {
	if !a.Active {
		return false
	}
	if a.ExpiresAt != nil {
		if time.Now().After(*a.ExpiresAt) {
			return false
		}
	}
	return true
}

func (a APIKey) TableName() string {
	return "public.api_keys"
}
