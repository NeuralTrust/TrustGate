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

package topic

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Score struct {
	Topic       string  `json:"topic"`
	Probability float64 `json:"probability"`
	Matched     bool    `json:"matched"`
}

type Classification struct {
	Scores       []Score  `json:"scores"`
	Matched      []string `json:"matched"`
	Windows      int      `json:"windows"`
	ModelVersion string   `json:"model_version,omitempty"`
}

const MaxBatchTexts = 128

var (
	ErrClassifierNotConfigured = errors.New("topic classifier: not configured")
	ErrClassifierUnauthorized  = errors.New("topic classifier: unauthorized")
	ErrQuotaExceeded           = errors.New("topic classifier: gateway quota exceeded")
)

type BackpressureError struct {
	RetryAfter time.Duration
}

func (e *BackpressureError) Error() string {
	return fmt.Sprintf("topic classifier: saturated, retry after %s", e.RetryAfter)
}

func CacheKey(gatewayID, textHash, catalogHash string, threshold *float64, modelVersion string) string {
	th := "default"
	if threshold != nil {
		th = strconv.FormatFloat(*threshold, 'g', -1, 64)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{gatewayID, textHash, catalogHash, th, modelVersion}, "\x00")))
	return hex.EncodeToString(sum[:])
}
