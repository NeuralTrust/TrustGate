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
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

const (
	MaxLabelsPerConsumer = 10
	MaxIDChars           = 128
	MaxNameChars         = 64
	MaxInstructionsChars = 2_000
	MaxExamples          = 5
	MaxExampleChars      = 500
)

var ErrInvalidLabels = fmt.Errorf("labels: %w", commonerrors.ErrValidation)

// Label is one traffic label a consumer is classified against. The catalog
// lives in the app; TrustGate only stores the resolved copy on the consumer.
type Label struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Instructions string   `json:"instructions"`
	Examples     []string `json:"examples,omitempty"`
}

// Ref is the id and name of a label, as reported in the classification event.
type Ref struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// NormalizeLabels returns a trimmed copy of labels. It never mutates its input.
func NormalizeLabels(labels []Label) []Label {
	if labels == nil {
		return nil
	}
	out := make([]Label, len(labels))
	for i, l := range labels {
		out[i] = Label{
			ID:           strings.TrimSpace(l.ID),
			Name:         strings.TrimSpace(l.Name),
			Instructions: strings.TrimSpace(l.Instructions),
		}
		if len(l.Examples) > 0 {
			out[i].Examples = make([]string, len(l.Examples))
			for j, e := range l.Examples {
				out[i].Examples[j] = strings.TrimSpace(e)
			}
		}
	}
	return out
}

// ValidateLabels checks a consumer's label list on its trimmed values without
// modifying it.
func ValidateLabels(labels []Label) error {
	if len(labels) > MaxLabelsPerConsumer {
		return fmt.Errorf("%w: at most %d labels are allowed, got %d", ErrInvalidLabels, MaxLabelsPerConsumer, len(labels))
	}
	ids := make(map[string]struct{}, len(labels))
	names := make(map[string]struct{}, len(labels))
	for i, l := range NormalizeLabels(labels) {
		if err := validateLabel(i, l); err != nil {
			return err
		}
		if _, dup := ids[l.ID]; dup {
			return fmt.Errorf("%w: label id %q is duplicated", ErrInvalidLabels, l.ID)
		}
		ids[l.ID] = struct{}{}
		key := strings.ToLower(l.Name)
		if _, dup := names[key]; dup {
			return fmt.Errorf("%w: label name %q is duplicated", ErrInvalidLabels, l.Name)
		}
		names[key] = struct{}{}
	}
	return nil
}

func validateLabel(i int, l Label) error {
	switch {
	case l.ID == "":
		return fmt.Errorf("%w: labels[%d].id is required", ErrInvalidLabels, i)
	case utf8.RuneCountInString(l.ID) > MaxIDChars:
		return fmt.Errorf("%w: labels[%d].id is longer than %d characters", ErrInvalidLabels, i, MaxIDChars)
	case l.Name == "":
		return fmt.Errorf("%w: labels[%d].name is required", ErrInvalidLabels, i)
	case utf8.RuneCountInString(l.Name) > MaxNameChars:
		return fmt.Errorf("%w: labels[%d].name is longer than %d characters", ErrInvalidLabels, i, MaxNameChars)
	case l.Instructions == "":
		return fmt.Errorf("%w: labels[%d].instructions is required", ErrInvalidLabels, i)
	case utf8.RuneCountInString(l.Instructions) > MaxInstructionsChars:
		return fmt.Errorf("%w: labels[%d].instructions is longer than %d characters", ErrInvalidLabels, i, MaxInstructionsChars)
	case len(l.Examples) > MaxExamples:
		return fmt.Errorf("%w: labels[%d] has more than %d examples", ErrInvalidLabels, i, MaxExamples)
	}
	for j, e := range l.Examples {
		if e == "" {
			return fmt.Errorf("%w: labels[%d].examples[%d] is empty", ErrInvalidLabels, i, j)
		}
		if utf8.RuneCountInString(e) > MaxExampleChars {
			return fmt.Errorf("%w: labels[%d].examples[%d] is longer than %d characters", ErrInvalidLabels, i, j, MaxExampleChars)
		}
	}
	return nil
}

// CatalogHash is an order-independent hash of a label list, covering every
// field the classifier sees.
func CatalogHash(labels []Label) string {
	sorted := slices.Clone(labels)
	slices.SortFunc(sorted, func(a, b Label) int { return cmp.Compare(a.ID, b.ID) })
	h := sha256.New()
	for _, l := range sorted {
		writeField(h, l.ID)
		writeField(h, l.Name)
		writeField(h, l.Instructions)
		writeField(h, strconv.Itoa(len(l.Examples)))
		for _, e := range l.Examples {
			writeField(h, e)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(w io.Writer, s string) {
	_, _ = io.WriteString(w, s)
	_, _ = w.Write([]byte{0})
}

// Refs returns the id and name of every label, in order.
func Refs(labels []Label) []Ref {
	out := make([]Ref, len(labels))
	for i, l := range labels {
		out[i] = Ref{ID: l.ID, Name: l.Name}
	}
	return out
}
