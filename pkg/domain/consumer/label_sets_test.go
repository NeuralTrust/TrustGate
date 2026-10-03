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

package consumer

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
)

func sentimentSet() trafficlabel.LabelSet {
	return trafficlabel.LabelSet{
		ID:           " set-1 ",
		Name:         " Sentiment ",
		Instructions: " overall mood ",
		Labels:       []trafficlabel.Label{{Name: " positive ", Description: " happy "}, {Name: "negative"}},
	}
}

func TestConsumerSetLabelSets(t *testing.T) {
	t.Parallel()
	sets := []trafficlabel.LabelSet{sentimentSet()}

	llm := &Consumer{Type: TypeLLM}
	if err := llm.SetLabelSets(sets); err != nil {
		t.Fatalf("SetLabelSets: %v", err)
	}
	got := llm.LabelSets[0]
	if got.ID != "set-1" || got.Name != "Sentiment" || got.Instructions != "overall mood" ||
		got.Labels[0] != (trafficlabel.Label{Name: "positive", Description: "happy"}) {
		t.Fatalf("label sets not normalized: %+v", got)
	}
	if sets[0].Name != " Sentiment " || sets[0].Labels[0].Name != " positive " {
		t.Fatal("SetLabelSets mutated its input")
	}

	if err := llm.SetLabelSets([]trafficlabel.LabelSet{}); err != nil || llm.LabelSets != nil {
		t.Fatalf("an empty list must clear the label sets, got %+v, %v", llm.LabelSets, err)
	}

	for _, typ := range []Type{TypeMCP, TypeA2A} {
		c := &Consumer{Type: typ}
		err := c.SetLabelSets(sets)
		if !errors.Is(err, ErrInvalidLabelSets) || !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("%s consumer accepted label sets: %v", typ, err)
		}
		if err := c.SetLabelSets(nil); err != nil {
			t.Fatalf("clearing a %s consumer must be allowed: %v", typ, err)
		}
	}

	keep := trafficlabel.LabelSet{ID: "keep", Name: "Keep", Labels: []trafficlabel.Label{{Name: "a"}, {Name: "b"}}}
	invalid := &Consumer{Type: TypeLLM, LabelSets: []trafficlabel.LabelSet{keep}}
	oneLabel := sentimentSet()
	oneLabel.Labels = oneLabel.Labels[:1]
	if err := invalid.SetLabelSets([]trafficlabel.LabelSet{oneLabel}); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("a set with a single label was accepted: %v", err)
	}
	if len(invalid.LabelSets) != 1 || invalid.LabelSets[0].ID != "keep" {
		t.Fatal("a rejected list must leave the label sets untouched")
	}
}
