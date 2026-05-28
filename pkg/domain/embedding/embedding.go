package embedding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

type Embedding struct {
	EntityID  string    `json:"entity_id"`
	Value     []float64 `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}

func (e *Embedding) ToBlob() ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("embedding is nil")
	}
	if e.Value == nil {
		return nil, fmt.Errorf("embedding value is nil")
	}
	float32Embedding := make([]float32, len(e.Value))
	for i, v := range e.Value {
		float32Embedding[i] = float32(v)
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, float32Embedding); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
