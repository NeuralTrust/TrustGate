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

package request

import (
	"errors"
	"slices"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func strPtr(v string) *string { return &v }

func TestUpdateConsumerRequest_ToType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   *string
		want *domain.Type
	}{
		{"omitted", nil, nil},
		{"empty", strPtr(""), nil},
		{"whitespace", strPtr("   "), nil},
		{"value", strPtr("MCP"), func() *domain.Type { v := domain.Type("MCP"); return &v }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := UpdateConsumerRequest{Type: tc.in}.ToType()
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("ToType() nilness mismatch: got=%v want=%v", got, tc.want)
			}
			if got != nil && *got != *tc.want {
				t.Fatalf("ToType() = %q, want %q", *got, *tc.want)
			}
		})
	}
}

func TestUpdateConsumerRequest_ToRegistryBindings(t *testing.T) {
	t.Parallel()
	first := ids.New[ids.RegistryKind]()
	second := ids.New[ids.RegistryKind]()
	weight := 40

	t.Run("omitted keeps current associations", func(t *testing.T) {
		t.Parallel()
		got, err := UpdateConsumerRequest{}.ToRegistryBindings()
		if err != nil {
			t.Fatalf("ToRegistryBindings() error: %v", err)
		}
		if got != nil {
			t.Fatalf("ToRegistryBindings() = %+v, want nil", got)
		}
	})

	t.Run("empty list detaches every registry", func(t *testing.T) {
		t.Parallel()
		got, err := UpdateConsumerRequest{Registries: &[]RegistryBindingRequest{}}.ToRegistryBindings()
		if err != nil {
			t.Fatalf("ToRegistryBindings() error: %v", err)
		}
		if got == nil || len(got.IDs) != 0 {
			t.Fatalf("ToRegistryBindings() = %+v, want empty binding set", got)
		}
	})

	t.Run("preserves order and weights", func(t *testing.T) {
		t.Parallel()
		got, err := UpdateConsumerRequest{Registries: &[]RegistryBindingRequest{
			{ID: first.String(), Weight: &weight},
			{ID: second.String()},
		}}.ToRegistryBindings()
		if err != nil {
			t.Fatalf("ToRegistryBindings() error: %v", err)
		}
		if len(got.IDs) != 2 || got.IDs[0] != first || got.IDs[1] != second {
			t.Fatalf("IDs = %v, want [%s %s]", got.IDs, first, second)
		}
		if got.Weights[first] != weight || got.Weights[second] != domain.DefaultRegistryWeight {
			t.Fatalf("Weights = %v", got.Weights)
		}
	})

	t.Run("rejects duplicates", func(t *testing.T) {
		t.Parallel()
		_, err := UpdateConsumerRequest{Registries: &[]RegistryBindingRequest{
			{ID: first.String()},
			{ID: first.String()},
		}}.ToRegistryBindings()
		if !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("err = %v, want ErrValidation", err)
		}
	})

	t.Run("rejects out of range weight", func(t *testing.T) {
		t.Parallel()
		tooBig := domain.MaxRegistryWeight + 1
		_, err := UpdateConsumerRequest{Registries: &[]RegistryBindingRequest{
			{ID: first.String(), Weight: &tooBig},
		}}.ToRegistryBindings()
		if !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("err = %v, want ErrValidation", err)
		}
	})
}

func TestUpdateConsumerRequest_Validate_RejectsPerBindingModelPolicies(t *testing.T) {
	t.Parallel()
	req := UpdateConsumerRequest{Registries: &[]RegistryBindingRequest{
		{ID: ids.New[ids.RegistryKind]().String(), ModelPolicies: &RegistryModelPolicyRequest{Default: "gpt-4o"}},
	}}
	if err := req.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

func TestUpdateConsumerRequest_ToAuthIDs(t *testing.T) {
	t.Parallel()
	first := ids.New[ids.AuthKind]()
	second := ids.New[ids.AuthKind]()

	cases := []struct {
		name    string
		in      *[]string
		want    *[]ids.AuthID
		wantErr error
	}{
		{name: "omitted keeps current associations", in: nil},
		{name: "empty list detaches every auth", in: &[]string{}, want: &[]ids.AuthID{}},
		{
			name: "replacement set",
			in:   &[]string{first.String(), " " + second.String() + " "},
			want: &[]ids.AuthID{first, second},
		},
		{name: "invalid id", in: &[]string{"not-a-uuid"}, wantErr: commonerrors.ErrValidation},
		{name: "duplicate id", in: &[]string{first.String(), first.String()}, wantErr: commonerrors.ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := UpdateConsumerRequest{Auths: tc.in}.ToAuthIDs()
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ToAuthIDs() error: %v", err)
			}
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("ToAuthIDs() nilness mismatch: got=%v want=%v", got, tc.want)
			}
			if got != nil && !slices.Equal(*got, *tc.want) {
				t.Fatalf("ToAuthIDs() = %v, want %v", *got, *tc.want)
			}
		})
	}
}

func TestUpdateConsumerRequest_Validate_CapsAuths(t *testing.T) {
	t.Parallel()
	atCap := make([]string, MaxAuthAssociations)
	for i := range atCap {
		atCap[i] = ids.New[ids.AuthKind]().String()
	}
	if err := (UpdateConsumerRequest{Auths: &atCap}).Validate(); err != nil {
		t.Fatalf("Validate() at the cap: %v", err)
	}
	overCap := append(atCap, ids.New[ids.AuthKind]().String())
	err := UpdateConsumerRequest{Auths: &overCap}.Validate()
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

func TestUpdateConsumerRequest_ToAuthIDs_KeepsParseCause(t *testing.T) {
	t.Parallel()
	_, err := UpdateConsumerRequest{Auths: &[]string{"not-a-uuid"}}.ToAuthIDs()
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
	if !strings.Contains(err.Error(), "uuid") {
		t.Fatalf("err = %q, want the underlying parse detail", err)
	}
}
