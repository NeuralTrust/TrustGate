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

package gateway

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func intPtr(v int) *int { return &v }

func TestResolveLimits_UnstampedNoCaps(t *testing.T) {
	t.Parallel()
	for _, tier := range []string{"standard", "free", ""} {
		t.Run(tier, func(t *testing.T) {
			_, ok := Entitlements{Tier: tier}.ResolveLimits()
			if ok {
				t.Fatal("expected unstamped entitlements to have no caps")
			}
		})
	}
}

func TestResolveLimits_StampedCaps(t *testing.T) {
	t.Parallel()
	e := Entitlements{
		Tier:          "free",
		BurstPerMin:   intPtr(12),
		QuotaPerMonth: intPtr(34),
		MaxInstances:  intPtr(5),
	}
	limits, ok := e.ResolveLimits()
	if !ok {
		t.Fatal("expected ok")
	}
	if limits.BurstPerMin != 12 || limits.QuotaPerMonth != 34 || limits.MaxInstances != 5 {
		t.Fatalf("got %+v", limits)
	}
}

func TestRequireStampedEntitlements_RejectsTierOnly(t *testing.T) {
	t.Parallel()
	_, err := RequireStampedEntitlements(Entitlements{Tier: "standard"})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

func TestRequireStampedEntitlements_AcceptsFullStamp(t *testing.T) {
	t.Parallel()
	got, err := RequireStampedEntitlements(Entitlements{
		Tier:          " Enterprise ",
		BurstPerMin:   intPtr(1_000),
		QuotaPerMonth: intPtr(0),
		MaxInstances:  intPtr(0),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Tier != "enterprise" {
		t.Fatalf("tier = %q", got.Tier)
	}
	if !got.HasStampedLimits() {
		t.Fatal("expected stamped limits")
	}
}

func TestNormalizeEntitlements_PartialStampRejected(t *testing.T) {
	t.Parallel()
	_, err := NormalizeEntitlements(Entitlements{Tier: "free", BurstPerMin: intPtr(60)})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

func TestNormalizeEntitlements_FullStampOK(t *testing.T) {
	t.Parallel()
	got, err := NormalizeEntitlements(Entitlements{
		Tier:          " Standard ",
		BurstPerMin:   intPtr(300),
		QuotaPerMonth: intPtr(100_000),
		MaxInstances:  intPtr(2),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Tier != "standard" {
		t.Fatalf("tier = %q", got.Tier)
	}
	if !got.HasStampedLimits() {
		t.Fatal("expected stamped limits")
	}
}
