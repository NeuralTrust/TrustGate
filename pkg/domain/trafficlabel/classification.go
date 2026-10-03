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

package trafficlabel

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Classification is the outcome of labeling one text: the ids of the labels
// that apply, which may be none, and what the classifier call cost.
type Classification struct {
	LabelIDs     []string      `json:"label_ids"`
	InputTokens  int           `json:"input_tokens,omitempty"`
	OutputTokens int           `json:"output_tokens,omitempty"`
	Latency      time.Duration `json:"latency,omitempty"`
}

// Cached returns the classification as stored in the cache: the labels only,
// since a cache hit costs nothing.
func (c Classification) Cached() Classification {
	return Classification{LabelIDs: slices.Clone(c.LabelIDs)}
}

// Matched resolves the label ids against the labels that were evaluated,
// keeping the order of the evaluated list.
func (c Classification) Matched(evaluated []Label) []Ref {
	out := make([]Ref, 0, len(c.LabelIDs))
	for _, l := range evaluated {
		if slices.Contains(c.LabelIDs, l.ID) {
			out = append(out, Ref{ID: l.ID, Name: l.Name})
		}
	}
	return out
}

var (
	// ErrClassifierUnavailable means the selected registry or model cannot
	// serve the classification: retrying will not help until the config changes.
	ErrClassifierUnavailable = errors.New("traffic labels: classifier unavailable")
	// ErrInvalidAnswer means the model answered with something that is not a
	// label list. It is about that one text, not about the provider.
	ErrInvalidAnswer = errors.New("traffic labels: classifier answer is not valid")
	ErrQuotaExceeded = errors.New("traffic labels: gateway quota exceeded")
)

// BackpressureError reports that the classifier's provider is saturated and
// asked to be left alone for RetryAfter.
type BackpressureError struct {
	RetryAfter time.Duration
}

func (e *BackpressureError) Error() string {
	return fmt.Sprintf("traffic labels: provider saturated, retry after %s", e.RetryAfter)
}

func CacheKey(gatewayID, textHash, catalogHash, registryID, model string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{gatewayID, textHash, catalogHash, registryID, model}, "\x00")))
	return hex.EncodeToString(sum[:])
}
