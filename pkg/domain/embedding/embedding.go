package embedding

import (
	"bytes"
	"encoding/binary"
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

func (e *Embedding) ToBlob() ([]byte, error) {
	float32Embedding := make([]float32, len(e.Value))
	for i, v := range e.Value {
		float32Embedding[i] = float32(v)
	}

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, float32Embedding)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
