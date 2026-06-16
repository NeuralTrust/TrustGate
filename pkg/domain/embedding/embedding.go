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
