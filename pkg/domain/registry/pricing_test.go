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

package registry

import (
	"errors"
	"testing"
)

func TestPricing_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pricing *Pricing
		wantErr bool
	}{
		{name: "nil", pricing: nil},
		{name: "empty", pricing: &Pricing{}},
		{
			name: "valid discount and overrides",
			pricing: &Pricing{
				Discount: 0.2,
				Overrides: map[string]PriceOverride{
					"gpt-4o":       {Input: 0.0000015, Output: 0.000006},
					"gpt-4o-mini*": {Input: 0.0000001, Output: 0.0000004},
				},
			},
		},
		{name: "discount at bounds", pricing: &Pricing{Discount: 1}},
		{name: "negative discount", pricing: &Pricing{Discount: -0.1}, wantErr: true},
		{name: "discount above one", pricing: &Pricing{Discount: 1.1}, wantErr: true},
		{
			name:    "empty override key",
			pricing: &Pricing{Overrides: map[string]PriceOverride{"  ": {Input: 1, Output: 1}}},
			wantErr: true,
		},
		{
			name:    "negative override",
			pricing: &Pricing{Overrides: map[string]PriceOverride{"gpt-4o": {Input: -1}}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.pricing.Validate()
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidPricing) {
					t.Fatalf("Validate() error = %v, want ErrInvalidPricing", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestPricing_IsZero(t *testing.T) {
	t.Parallel()
	if !((*Pricing)(nil)).IsZero() {
		t.Fatal("nil pricing should be zero")
	}
	if !(&Pricing{}).IsZero() {
		t.Fatal("empty pricing should be zero")
	}
	if (&Pricing{Discount: 0.1}).IsZero() {
		t.Fatal("discount-only pricing should not be zero")
	}
}
