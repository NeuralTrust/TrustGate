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

func labels(n int) []Label {
	out := make([]Label, n)
	for i := range out {
		out[i] = Label{ID: fmt.Sprintf("id-%d", i), Name: fmt.Sprintf("label-%d", i), Instructions: "applies when"}
	}
	return out
}

func TestValidateLabels(t *testing.T) {
	t.Parallel()

	one := func(mut func(*Label)) []Label {
		l := Label{ID: "a", Name: "Billing", Instructions: "Refunds", Examples: []string{"where is my refund"}}
		mut(&l)
		return []Label{l}
	}
	tests := []struct {
		name    string
		labels  []Label
		wantErr bool
	}{
		{name: "nil clears", labels: nil},
		{name: "empty clears", labels: []Label{}},
		{name: "one label", labels: one(func(*Label) {})},
		{name: "the maximum", labels: labels(MaxLabelsPerConsumer)},
		{name: "over the maximum", labels: labels(MaxLabelsPerConsumer + 1), wantErr: true},
		{name: "blank id", labels: one(func(l *Label) { l.ID = " " }), wantErr: true},
		{name: "id too long", labels: one(func(l *Label) { l.ID = strings.Repeat("i", MaxIDChars+1) }), wantErr: true},
		{name: "blank name", labels: one(func(l *Label) { l.Name = " " }), wantErr: true},
		{name: "name at the limit", labels: one(func(l *Label) { l.Name = strings.Repeat("é", MaxNameChars) })},
		{name: "name over the limit", labels: one(func(l *Label) { l.Name = strings.Repeat("n", MaxNameChars+1) }), wantErr: true},
		{name: "blank instructions", labels: one(func(l *Label) { l.Instructions = "" }), wantErr: true},
		{name: "instructions at the limit", labels: one(func(l *Label) { l.Instructions = strings.Repeat("é", MaxInstructionsChars) })},
		{name: "instructions over the limit", labels: one(func(l *Label) { l.Instructions = strings.Repeat("i", MaxInstructionsChars+1) }), wantErr: true},
		{name: "no examples", labels: one(func(l *Label) { l.Examples = nil })},
		{name: "maximum examples", labels: one(func(l *Label) { l.Examples = []string{"a", "b", "c", "d", "e"} })},
		{name: "too many examples", labels: one(func(l *Label) { l.Examples = []string{"a", "b", "c", "d", "e", "f"} }), wantErr: true},
		{name: "blank example", labels: one(func(l *Label) { l.Examples = []string{" "} }), wantErr: true},
		{name: "example over the limit", labels: one(func(l *Label) { l.Examples = []string{strings.Repeat("e", MaxExampleChars+1)} }), wantErr: true},
		{
			name:    "duplicated id",
			labels:  []Label{{ID: "a", Name: "One", Instructions: "i"}, {ID: " a ", Name: "Two", Instructions: "i"}},
			wantErr: true,
		},
		{
			name:    "duplicated name ignoring case",
			labels:  []Label{{ID: "a", Name: "Billing", Instructions: "i"}, {ID: "b", Name: " billing ", Instructions: "i"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateLabels(tt.labels)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !errors.Is(err, ErrInvalidLabels) || !errors.Is(err, commonerrors.ErrValidation) {
					t.Fatalf("error %v does not wrap ErrInvalidLabels and ErrValidation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNormalizeLabels(t *testing.T) {
	t.Parallel()
	if NormalizeLabels(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	src := []Label{{ID: " a ", Name: " Billing ", Instructions: " Refunds ", Examples: []string{" x "}}}
	got := NormalizeLabels(src)
	if got[0].ID != "a" || got[0].Name != "Billing" || got[0].Instructions != "Refunds" || got[0].Examples[0] != "x" {
		t.Fatalf("not trimmed: %+v", got[0])
	}
	if src[0].Name != " Billing " || src[0].Examples[0] != " x " {
		t.Fatalf("NormalizeLabels mutated its input: %+v", src[0])
	}
}

func TestCatalogHash(t *testing.T) {
	t.Parallel()

	a := []Label{{ID: "1", Name: "billing", Instructions: "refunds"}, {ID: "2", Name: "legal", Instructions: "contracts"}}
	b := []Label{{ID: "2", Name: "legal", Instructions: "contracts"}, {ID: "1", Name: "billing", Instructions: "refunds"}}
	if CatalogHash(a) != CatalogHash(b) {
		t.Fatal("hash depends on label order")
	}
	changed := []Label{{ID: "1", Name: "billing", Instructions: "invoices"}, {ID: "2", Name: "legal", Instructions: "contracts"}}
	if CatalogHash(a) == CatalogHash(changed) {
		t.Fatal("hash ignores an instructions change")
	}
	withExample := []Label{{ID: "1", Name: "billing", Instructions: "refunds", Examples: []string{"x"}}, {ID: "2", Name: "legal", Instructions: "contracts"}}
	if CatalogHash(a) == CatalogHash(withExample) {
		t.Fatal("hash ignores examples")
	}
	shifted := []Label{{ID: "1", Name: "bil", Instructions: "lingrefunds"}, {ID: "2", Name: "legal", Instructions: "contracts"}}
	if CatalogHash(a) == CatalogHash(shifted) {
		t.Fatal("hash does not separate name from instructions")
	}
	if a[0].ID != "1" {
		t.Fatal("CatalogHash reordered its input")
	}
}

func TestClassificationMatched(t *testing.T) {
	t.Parallel()
	evaluated := []Label{{ID: "1", Name: "billing"}, {ID: "2", Name: "legal"}, {ID: "3", Name: "sales"}}
	cls := Classification{LabelIDs: []string{"3", "1"}}
	got := cls.Matched(evaluated)
	if len(got) != 2 || got[0] != (Ref{ID: "1", Name: "billing"}) || got[1] != (Ref{ID: "3", Name: "sales"}) {
		t.Fatalf("Matched() = %+v", got)
	}
	if got := (Classification{}).Matched(evaluated); got == nil || len(got) != 0 {
		t.Fatalf("no match must be an empty list, got %#v", got)
	}
	if refs := Refs(evaluated); len(refs) != 3 || refs[1] != (Ref{ID: "2", Name: "legal"}) {
		t.Fatalf("Refs() = %+v", refs)
	}
}

func TestClassificationCachedDropsCost(t *testing.T) {
	t.Parallel()
	cls := Classification{LabelIDs: []string{"1"}, InputTokens: 10, OutputTokens: 2, Latency: 5}
	got := cls.Cached()
	if got.InputTokens != 0 || got.OutputTokens != 0 || got.Latency != 0 || len(got.LabelIDs) != 1 {
		t.Fatalf("Cached() = %+v", got)
	}
}
