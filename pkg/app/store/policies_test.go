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

package store

import (
	"context"
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

type fakePolicyRepo struct {
	fakePolicies
	deleted []string
}

func (f *fakePolicyRepo) ListPolicies(context.Context, int, int) ([]*storeaccessdomain.Policy, int, error) {
	return f.items, len(f.items), nil
}

func (f *fakePolicyRepo) UpsertPolicy(_ context.Context, p *storeaccessdomain.Policy) error {
	for i, existing := range f.items {
		if existing.PrincipalType == p.PrincipalType && existing.PrincipalID == p.PrincipalID {
			f.items[i] = p
			return nil
		}
	}
	f.items = append(f.items, p)
	return nil
}

func (f *fakePolicyRepo) DeletePolicy(_ context.Context, _ ids.GatewayID, typ storeaccessdomain.PrincipalType, id string) error {
	f.deleted = append(f.deleted, string(typ)+"/"+id)
	kept := f.items[:0]
	for _, p := range f.items {
		if p.PrincipalType != typ || p.PrincipalID != id {
			kept = append(kept, p)
		}
	}
	f.items = kept
	return nil
}

func TestPolicyService_SetUpsertsClearsAndSignals(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	repo := &fakePolicyRepo{}
	sig := &countingSignaler{}
	svc, err := NewPolicyService(repo, sig)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}
	p, err := svc.Set(context.Background(), SetPolicyRequest{GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalUser, PrincipalID: "ana", Mode: "curated"})
	if err != nil || p == nil || p.Mode != "curated" {
		t.Fatalf("Set: %+v / %v", p, err)
	}
	got, _ := svc.ListPoliciesByGateway(context.Background(), gw)
	if len(got) != 1 || sig.n != 1 {
		t.Fatalf("expected one policy and one signal, got %d / %d", len(got), sig.n)
	}
	// Empty mode clears the policy (back to the gateway default).
	cleared, err := svc.Set(context.Background(), SetPolicyRequest{GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalUser, PrincipalID: "ana"})
	if err != nil || cleared != nil {
		t.Fatalf("clear must return nil policy, got %+v / %v", cleared, err)
	}
	if len(repo.items) != 0 || len(repo.deleted) != 1 || sig.n != 2 {
		t.Fatalf("clear must delete and signal, items=%d deleted=%v signals=%d", len(repo.items), repo.deleted, sig.n)
	}
	if _, err := svc.Set(context.Background(), SetPolicyRequest{GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalUser, PrincipalID: "ana", Mode: "everything"}); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("invalid mode must be a validation error, got %v", err)
	}
	if _, err := svc.Set(context.Background(), SetPolicyRequest{GatewayID: gw, PrincipalType: "team", PrincipalID: "ana"}); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("clearing an invalid principal type must be a validation error, got %v", err)
	}
}
