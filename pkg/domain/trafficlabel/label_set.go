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
	MaxLabelSetsPerConsumer = 10
	MaxIDChars              = 128
	MaxNameChars            = 64
	MaxInstructionsChars    = 2_000
	MinLabelsPerSet         = 2
	MaxLabelsPerSet         = 20
	MaxDescriptionChars     = 500
)

// catalogHashVersion keeps hashes of this shape apart from any earlier one,
// so a cached result of another catalog format is never reused.
const catalogHashVersion = "label-sets/v2"

var ErrInvalidLabelSets = fmt.Errorf("label_sets: %w", commonerrors.ErrValidation)

// Label is one of the labels of a set: the classifier picks at most one of
// them per set.
type Label struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// LabelSet is one classification a consumer's traffic goes through: its
// instructions and the labels the classifier chooses from. The catalog lives
// in the app; TrustGate only stores the resolved copy on the consumer.
type LabelSet struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Instructions string  `json:"instructions"`
	Labels       []Label `json:"labels"`
}

// NormalizeLabelSets returns a trimmed copy of sets. It never mutates its input.
func NormalizeLabelSets(sets []LabelSet) []LabelSet {
	if sets == nil {
		return nil
	}
	out := make([]LabelSet, len(sets))
	for i, s := range sets {
		out[i] = LabelSet{
			ID:           strings.TrimSpace(s.ID),
			Name:         strings.TrimSpace(s.Name),
			Instructions: strings.TrimSpace(s.Instructions),
		}
		if s.Labels != nil {
			out[i].Labels = make([]Label, len(s.Labels))
			for j, l := range s.Labels {
				out[i].Labels[j] = Label{Name: strings.TrimSpace(l.Name), Description: strings.TrimSpace(l.Description)}
			}
		}
	}
	return out
}

// ValidateLabelSets checks a consumer's label sets on their trimmed values
// without modifying them.
func ValidateLabelSets(sets []LabelSet) error {
	if len(sets) > MaxLabelSetsPerConsumer {
		return fmt.Errorf("%w: at most %d label sets are allowed, got %d", ErrInvalidLabelSets, MaxLabelSetsPerConsumer, len(sets))
	}
	ids := make(map[string]struct{}, len(sets))
	names := make(map[string]struct{}, len(sets))
	for i, s := range NormalizeLabelSets(sets) {
		if err := validateLabelSet(i, s); err != nil {
			return err
		}
		if _, dup := ids[s.ID]; dup {
			return fmt.Errorf("%w: label set id %q is duplicated", ErrInvalidLabelSets, s.ID)
		}
		ids[s.ID] = struct{}{}
		key := strings.ToLower(s.Name)
		if _, dup := names[key]; dup {
			return fmt.Errorf("%w: label set name %q is duplicated", ErrInvalidLabelSets, s.Name)
		}
		names[key] = struct{}{}
	}
	return nil
}

func validateLabelSet(i int, s LabelSet) error {
	switch {
	case s.ID == "":
		return fmt.Errorf("%w: label_sets[%d].id is required", ErrInvalidLabelSets, i)
	case utf8.RuneCountInString(s.ID) > MaxIDChars:
		return fmt.Errorf("%w: label_sets[%d].id is longer than %d characters", ErrInvalidLabelSets, i, MaxIDChars)
	case s.Name == "":
		return fmt.Errorf("%w: label_sets[%d].name is required", ErrInvalidLabelSets, i)
	case utf8.RuneCountInString(s.Name) > MaxNameChars:
		return fmt.Errorf("%w: label_sets[%d].name is longer than %d characters", ErrInvalidLabelSets, i, MaxNameChars)
	case utf8.RuneCountInString(s.Instructions) > MaxInstructionsChars:
		return fmt.Errorf("%w: label_sets[%d].instructions is longer than %d characters", ErrInvalidLabelSets, i, MaxInstructionsChars)
	case len(s.Labels) < MinLabelsPerSet || len(s.Labels) > MaxLabelsPerSet:
		return fmt.Errorf("%w: label_sets[%d] must have %d to %d labels, got %d", ErrInvalidLabelSets, i, MinLabelsPerSet, MaxLabelsPerSet, len(s.Labels))
	}
	names := make(map[string]struct{}, len(s.Labels))
	for j, l := range s.Labels {
		switch {
		case l.Name == "":
			return fmt.Errorf("%w: label_sets[%d].labels[%d].name is required", ErrInvalidLabelSets, i, j)
		case utf8.RuneCountInString(l.Name) > MaxNameChars:
			return fmt.Errorf("%w: label_sets[%d].labels[%d].name is longer than %d characters", ErrInvalidLabelSets, i, j, MaxNameChars)
		case utf8.RuneCountInString(l.Description) > MaxDescriptionChars:
			return fmt.Errorf("%w: label_sets[%d].labels[%d].description is longer than %d characters", ErrInvalidLabelSets, i, j, MaxDescriptionChars)
		}
		key := strings.ToLower(l.Name)
		if _, dup := names[key]; dup {
			return fmt.Errorf("%w: label_sets[%d] has the label %q twice", ErrInvalidLabelSets, i, l.Name)
		}
		names[key] = struct{}{}
	}
	return nil
}

// CatalogHash is an order-independent hash of a consumer's label sets (the
// order of the sets and of the labels in each set does not matter), covering
// every field the classifier sees.
func CatalogHash(sets []LabelSet) string {
	sorted := slices.Clone(sets)
	slices.SortFunc(sorted, func(a, b LabelSet) int { return cmp.Compare(a.ID, b.ID) })
	h := sha256.New()
	writeField(h, catalogHashVersion)
	for _, s := range sorted {
		writeField(h, s.ID)
		writeField(h, s.Name)
		writeField(h, s.Instructions)
		writeField(h, strconv.Itoa(len(s.Labels)))
		labels := slices.Clone(s.Labels)
		slices.SortFunc(labels, func(a, b Label) int {
			return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Description, b.Description))
		})
		for _, l := range labels {
			writeField(h, l.Name)
			writeField(h, l.Description)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(w io.Writer, s string) {
	_, _ = io.WriteString(w, s)
	_, _ = w.Write([]byte{0})
}

// MatchLabel returns the set's spelling of name, compared ignoring case and
// surrounding spaces, and whether the set has such a label.
func (s LabelSet) MatchLabel(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	for _, l := range s.Labels {
		if strings.EqualFold(l.Name, name) {
			return l.Name, true
		}
	}
	return "", false
}

func cloneLabelSets(sets []LabelSet) []LabelSet {
	if sets == nil {
		return nil
	}
	out := make([]LabelSet, len(sets))
	for i, s := range sets {
		out[i] = s
		out[i].Labels = slices.Clone(s.Labels)
	}
	return out
}
