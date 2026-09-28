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

// Score is the verdict of topic-guard for one topic of the catalog.
type Score struct {
	Topic       string  `json:"topic"`
	Probability float64 `json:"probability"`
	Matched     bool    `json:"matched"`
}

// Classification is the topic-guard result for one text: a score for every
// topic of the catalog, and the topics that cleared the threshold.
type Classification struct {
	Scores       []Score  `json:"scores"`
	Matched      []string `json:"matched"`
	Windows      int      `json:"windows"`
	ModelVersion string   `json:"model_version,omitempty"`
}

// MaxBatchTexts is the largest number of texts topic-guard scores in one call.
const MaxBatchTexts = 128

var (
	// ErrClassifierNotConfigured is returned when the data plane has no
	// topic-guard endpoint or credentials.
	ErrClassifierNotConfigured = errors.New("topic classifier: not configured")
	// ErrClassifierUnauthorized is returned when topic-guard rejects the token.
	ErrClassifierUnauthorized = errors.New("topic classifier: unauthorized")
	// ErrQuotaExceeded is returned when a gateway has queued more requests
	// than its share in the current window. The request is dropped.
	ErrQuotaExceeded = errors.New("topic classifier: gateway quota exceeded")
)

// BackpressureError reports that topic-guard is saturated and asks callers to
// wait RetryAfter before sending more. It is not a failure of the service.
type BackpressureError struct {
	RetryAfter time.Duration
}

func (e *BackpressureError) Error() string {
	return fmt.Sprintf("topic classifier: saturated, retry after %s", e.RetryAfter)
}

// CacheKey identifies a classification by everything that determines it: the
// text, the catalog, the threshold and the model version that scored it.
func CacheKey(textHash, catalogHash string, threshold *float64, modelVersion string) string {
	th := "default"
	if threshold != nil {
		th = strconv.FormatFloat(*threshold, 'g', -1, 64)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{textHash, catalogHash, th, modelVersion}, "\x00")))
	return hex.EncodeToString(sum[:])
}
