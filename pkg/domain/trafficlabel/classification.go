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

// Result is the label the classifier picked for one label set, or "" when
// none of the set's labels applies.
type Result struct {
	LabelSetID string `json:"label_set_id"`
	Label      string `json:"label"`
}

// SetResult is the outcome for one evaluated label set, as reported in the
// classification event: Label is "" when the request is unlabeled for the set.
type SetResult struct {
	LabelSetID   string
	LabelSetName string
	Label        string
}

// Classification is the outcome of labeling one text: at most one label per
// label set, and what the classifier call cost.
type Classification struct {
	Results      []Result      `json:"results"`
	InputTokens  int           `json:"input_tokens,omitempty"`
	OutputTokens int           `json:"output_tokens,omitempty"`
	Latency      time.Duration `json:"latency,omitempty"`
}

// Cached returns the classification as stored in the cache: the results
// only, since a cache hit costs nothing.
func (c Classification) Cached() Classification {
	return Classification{Results: slices.Clone(c.Results)}
}

// Resolve returns one result per evaluated label set, in the order of sets.
// A set the classification has no result for, or whose result is not one of
// the set's labels, is unlabeled; labels take the set's spelling.
func (c Classification) Resolve(sets []LabelSet) []SetResult {
	picked := make(map[string]string, len(c.Results))
	for _, r := range c.Results {
		if _, seen := picked[r.LabelSetID]; !seen {
			picked[r.LabelSetID] = r.Label
		}
	}
	out := make([]SetResult, len(sets))
	for i, s := range sets {
		label, _ := s.MatchLabel(picked[s.ID])
		out[i] = SetResult{LabelSetID: s.ID, LabelSetName: s.Name, Label: label}
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
