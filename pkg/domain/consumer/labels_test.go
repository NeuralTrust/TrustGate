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

func TestConsumerSetLabels(t *testing.T) {
	t.Parallel()
	billing := []trafficlabel.Label{{ID: " l-1 ", Name: " Billing ", Instructions: " refunds ", Examples: []string{" refund? "}}}

	llm := &Consumer{Type: TypeLLM}
	if err := llm.SetLabels(billing); err != nil {
		t.Fatalf("SetLabels: %v", err)
	}
	if got := llm.Labels[0]; got.ID != "l-1" || got.Name != "Billing" || got.Instructions != "refunds" || got.Examples[0] != "refund?" {
		t.Fatalf("labels not normalized: %+v", got)
	}
	if billing[0].Name != " Billing " {
		t.Fatal("SetLabels mutated its input")
	}

	if err := llm.SetLabels([]trafficlabel.Label{}); err != nil || llm.Labels != nil {
		t.Fatalf("an empty list must clear the labels, got %+v, %v", llm.Labels, err)
	}

	for _, typ := range []Type{TypeMCP, TypeA2A} {
		c := &Consumer{Type: typ}
		err := c.SetLabels(billing)
		if !errors.Is(err, ErrInvalidLabels) || !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("%s consumer accepted labels: %v", typ, err)
		}
		if err := c.SetLabels(nil); err != nil {
			t.Fatalf("clearing a %s consumer must be allowed: %v", typ, err)
		}
	}

	invalid := &Consumer{Type: TypeLLM, Labels: []trafficlabel.Label{{ID: "keep", Name: "Keep", Instructions: "x"}}}
	if err := invalid.SetLabels([]trafficlabel.Label{{ID: "a", Instructions: "x"}}); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("an unnamed label was accepted: %v", err)
	}
	if len(invalid.Labels) != 1 || invalid.Labels[0].ID != "keep" {
		t.Fatal("a rejected list must leave the labels untouched")
	}
}
