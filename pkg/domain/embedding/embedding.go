package embedding

import (
	"time"
)

type Embedding struct {
	EntityID  string    `json:"entity_id"`
	Value     []float64 `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}
