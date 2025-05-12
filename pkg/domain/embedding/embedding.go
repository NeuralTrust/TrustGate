package embedding

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
)

type Embedding struct {
	EntityID  string    `json:"entity_id"`
	Value     []float64 `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}

type Config struct {
	Provider    string                 `json:"provider"`
	Model       string                 `json:"model"`
	Credentials domain.CredentialsJSON `json:"credentials,omitempty" gorm:"type:jsonb"`
}
