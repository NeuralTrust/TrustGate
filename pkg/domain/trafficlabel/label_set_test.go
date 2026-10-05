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
	"errors"
	"fmt"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func sentiment() LabelSet {
	return LabelSet{
		ID:           "set-sentiment",
		Name:         "Sentiment analysis",
		Instructions: "Classify the overall sentiment of the user's message",
		Labels: []Label{
			{Name: "positive", Description: "Happy or satisfied"},
			{Name: "negative", Description: "Angry or disappointed"},
			{Name: "neutral"},
		},
	}
}

func labelSets(n int) []LabelSet {
	out := make([]LabelSet, n)
	for i := range out {
		out[i] = LabelSet{
			ID:     fmt.Sprintf("id-%d", i),
			Name:   fmt.Sprintf("set-%d", i),
			Labels: []Label{{Name: "yes"}, {Name: "no"}},
		}
	}
	return out
}

func manyLabels(n int) []Label {
	out := make([]Label, n)
	for i := range out {
		out[i] = Label{Name: fmt.Sprintf("label-%d", i)}
	}
	return out
}

func TestValidateLabelSets(t *testing.T) {
	t.Parallel()

	one := func(mut func(*LabelSet)) []LabelSet {
		s := sentiment()
		mut(&s)
		return []LabelSet{s}
	}
	tests := []struct {
		name    string
		sets    []LabelSet
		wantErr bool
	}{
		{name: "nil clears", sets: nil},
		{name: "empty clears", sets: []LabelSet{}},
		{name: "one set", sets: one(func(*LabelSet) {})},
		{name: "the maximum of sets", sets: labelSets(MaxLabelSetsPerConsumer)},
		{name: "over the maximum of sets", sets: labelSets(MaxLabelSetsPerConsumer + 1), wantErr: true},
		{name: "blank id", sets: one(func(s *LabelSet) { s.ID = " " }), wantErr: true},
		{name: "id too long", sets: one(func(s *LabelSet) { s.ID = strings.Repeat("i", MaxIDChars+1) }), wantErr: true},
		{name: "blank name", sets: one(func(s *LabelSet) { s.Name = " " }), wantErr: true},
		{name: "name at the limit", sets: one(func(s *LabelSet) { s.Name = strings.Repeat("é", MaxNameChars) })},
		{name: "name over the limit", sets: one(func(s *LabelSet) { s.Name = strings.Repeat("n", MaxNameChars+1) }), wantErr: true},
		{name: "no instructions", sets: one(func(s *LabelSet) { s.Instructions = "" })},
		{name: "instructions at the limit", sets: one(func(s *LabelSet) { s.Instructions = strings.Repeat("é", MaxInstructionsChars) })},
		{name: "instructions over the limit", sets: one(func(s *LabelSet) { s.Instructions = strings.Repeat("i", MaxInstructionsChars+1) }), wantErr: true},
		{name: "no labels", sets: one(func(s *LabelSet) { s.Labels = nil }), wantErr: true},
		{name: "a single label", sets: one(func(s *LabelSet) { s.Labels = s.Labels[:1] }), wantErr: true},
		{name: "the minimum of labels", sets: one(func(s *LabelSet) { s.Labels = s.Labels[:MinLabelsPerSet] })},
		{name: "the maximum of labels", sets: one(func(s *LabelSet) { s.Labels = manyLabels(MaxLabelsPerSet) })},
		{name: "over the maximum of labels", sets: one(func(s *LabelSet) { s.Labels = manyLabels(MaxLabelsPerSet + 1) }), wantErr: true},
		{name: "blank label name", sets: one(func(s *LabelSet) { s.Labels[0].Name = " " }), wantErr: true},
		{name: "label name at the limit", sets: one(func(s *LabelSet) { s.Labels[0].Name = strings.Repeat("é", MaxNameChars) })},
		{name: "label name over the limit", sets: one(func(s *LabelSet) { s.Labels[0].Name = strings.Repeat("n", MaxNameChars+1) }), wantErr: true},
		{name: "description at the limit", sets: one(func(s *LabelSet) { s.Labels[0].Description = strings.Repeat("é", MaxDescriptionChars) })},
		{name: "description over the limit", sets: one(func(s *LabelSet) { s.Labels[0].Description = strings.Repeat("d", MaxDescriptionChars+1) }), wantErr: true},
		{name: "duplicated label name ignoring case", sets: one(func(s *LabelSet) { s.Labels[1].Name = " Positive " }), wantErr: true},
		{name: "the same label name in two sets", sets: labelSets(2)},
		{
			name: "duplicated id",
			sets: func() []LabelSet {
				sets := labelSets(2)
				sets[1].ID = " " + sets[0].ID + " "
				return sets
			}(),
			wantErr: true,
		},
		{
			name: "duplicated set name ignoring case",
			sets: func() []LabelSet {
				sets := labelSets(2)
				sets[1].Name = strings.ToUpper(sets[0].Name)
				return sets
			}(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateLabelSets(tt.sets)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !errors.Is(err, ErrInvalidLabelSets) || !errors.Is(err, commonerrors.ErrValidation) {
					t.Fatalf("error %v does not wrap ErrInvalidLabelSets and ErrValidation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNormalizeLabelSets(t *testing.T) {
	t.Parallel()
	if NormalizeLabelSets(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	src := []LabelSet{{ID: " a ", Name: " Sentiment ", Instructions: " Mood ", Labels: []Label{{Name: " positive ", Description: " happy "}}}}
	got := NormalizeLabelSets(src)
	if got[0].ID != "a" || got[0].Name != "Sentiment" || got[0].Instructions != "Mood" ||
		got[0].Labels[0] != (Label{Name: "positive", Description: "happy"}) {
		t.Fatalf("not trimmed: %+v", got[0])
	}
	if src[0].Name != " Sentiment " || src[0].Labels[0].Name != " positive " {
		t.Fatalf("NormalizeLabelSets mutated its input: %+v", src[0])
	}
}

func TestCatalogHash(t *testing.T) {
	t.Parallel()

	topic := LabelSet{ID: "set-topic", Name: "Topic", Labels: []Label{{Name: "billing"}, {Name: "legal"}}}
	a := []LabelSet{sentiment(), topic}
	b := []LabelSet{topic, sentiment()}
	if CatalogHash(a) != CatalogHash(b) {
		t.Fatal("hash depends on the order of the sets")
	}
	reordered := sentiment()
	reordered.Labels[0], reordered.Labels[2] = reordered.Labels[2], reordered.Labels[0]
	if CatalogHash(a) != CatalogHash([]LabelSet{reordered, topic}) {
		t.Fatal("hash depends on the order of the labels")
	}
	for name, mut := range map[string]func(*LabelSet){
		"instructions":      func(s *LabelSet) { s.Instructions = "other" },
		"set name":          func(s *LabelSet) { s.Name = "other" },
		"label name":        func(s *LabelSet) { s.Labels[0].Name = "other" },
		"label description": func(s *LabelSet) { s.Labels[0].Description = "other" },
		"a new label":       func(s *LabelSet) { s.Labels = append(s.Labels, Label{Name: "mixed"}) },
		"name/description boundary": func(s *LabelSet) {
			s.Labels[0] = Label{Name: "posit", Description: "iveHappy or satisfied"}
		},
	} {
		changed := sentiment()
		mut(&changed)
		if CatalogHash(a) == CatalogHash([]LabelSet{changed, topic}) {
			t.Fatalf("hash ignores a change of %s", name)
		}
	}
	if a[0].ID != "set-sentiment" || a[0].Labels[0].Name != "positive" {
		t.Fatal("CatalogHash reordered its input")
	}
}

func TestLabelSetMatchLabel(t *testing.T) {
	t.Parallel()
	s := sentiment()
	for in, want := range map[string]string{"positive": "positive", " NEGATIVE ": "negative", "Neutral": "neutral"} {
		got, ok := s.MatchLabel(in)
		if !ok || got != want {
			t.Fatalf("MatchLabel(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "mixed", "posit"} {
		if got, ok := s.MatchLabel(in); ok || got != "" {
			t.Fatalf("MatchLabel(%q) = %q, %v; want no match", in, got, ok)
		}
	}
}

func TestClassificationResolve(t *testing.T) {
	t.Parallel()
	topic := LabelSet{ID: "set-topic", Name: "Topic", Labels: []Label{{Name: "billing"}, {Name: "legal"}}}
	lang := LabelSet{ID: "set-lang", Name: "Language", Labels: []Label{{Name: "en"}, {Name: "es"}}}
	evaluated := []LabelSet{sentiment(), topic, lang}
	cls := Classification{Results: []Result{
		{LabelSetID: "set-topic", Label: "unknown"},
		{LabelSetID: "set-sentiment", Label: "Negative"},
		{LabelSetID: "set-gone", Label: "billing"},
	}}
	got := cls.Resolve(evaluated)
	want := []SetResult{
		{LabelSetID: "set-sentiment", LabelSetName: "Sentiment analysis", Label: "negative"},
		{LabelSetID: "set-topic", LabelSetName: "Topic", Label: ""},
		{LabelSetID: "set-lang", LabelSetName: "Language", Label: ""},
	}
	if len(got) != len(want) {
		t.Fatalf("Resolve() = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Resolve()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if got := (Classification{}).Resolve(nil); got == nil || len(got) != 0 {
		t.Fatalf("no sets must be an empty list, got %#v", got)
	}
}

func TestClassificationCachedDropsCost(t *testing.T) {
	t.Parallel()
	cls := Classification{Results: []Result{{LabelSetID: "1", Label: "a"}}, InputTokens: 10, OutputTokens: 2, Latency: 5}
	got := cls.Cached()
	if got.InputTokens != 0 || got.OutputTokens != 0 || got.Latency != 0 || len(got.Results) != 1 {
		t.Fatalf("Cached() = %+v", got)
	}
}
