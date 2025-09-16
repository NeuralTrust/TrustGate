package apikey

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database/types"
	"github.com/google/uuid"
)

type APIKey struct {
	ID        uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey"`
	Key       string          `json:"key" gorm:"index"`
	Name      string          `json:"name"`
	Active    bool            `json:"active"`
	GatewayID uuid.UUID       `json:"gateway_id" gorm:"type:uuid;index"`
	Policies  types.UUIDArray `json:"policies,omitempty" gorm:"type:uuid[]"`
	ExpiresAt *time.Time      `json:"expires_at"`
	CreatedAt time.Time       `json:"created_at"`
}

func (a APIKey) TableName() string {
	return "public.api_keys"
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
