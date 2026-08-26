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
	"time"

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

func TestResolveRetention_UnstampedReportsNoWindow(t *testing.T) {
	t.Parallel()
	for name, e := range map[string]Entitlements{
		"absent":     {Tier: "free"},
		"negative":   {Tier: "free", RetentionDays: intPtr(-1)},
		"rate-limit": {Tier: "free", BurstPerMin: intPtr(60), QuotaPerMonth: intPtr(10), MaxInstances: intPtr(1)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, ok := e.ResolveRetention(); ok {
				t.Fatal("expected no retention window")
			}
		})
	}
}

// 0 is the same unlimited sentinel the other caps use. It must not be confused
// with "never stamped", which emits no expiry and defers to the sink's fallback.
func TestResolveRetention_ZeroMeansUnlimited(t *testing.T) {
	t.Parallel()
	got, ok := Entitlements{Tier: "enterprise", RetentionDays: intPtr(0)}.ResolveRetention()
	if !ok {
		t.Fatal("unlimited must resolve to a window, not to no stamp")
	}
	if got != UnlimitedRetentionWindow {
		t.Fatalf("window = %v, want %v", got, UnlimitedRetentionWindow)
	}
}

// Pinned so TrustGate and TrustGuard cannot drift on what unlimited means, and so
// the expiry stays inside the ClickHouse DateTime range (uint32 seconds, max 2106).
func TestUnlimitedRetentionWindowIsPinnedAndBounded(t *testing.T) {
	t.Parallel()
	if want := 3650 * 24 * time.Hour; UnlimitedRetentionWindow != want {
		t.Fatalf("UnlimitedRetentionWindow = %v, want %v (must match TrustGuard)", UnlimitedRetentionWindow, want)
	}
	latest := time.Now().Add(UnlimitedRetentionWindow)
	if ceiling := time.Date(2106, 1, 1, 0, 0, 0, 0, time.UTC); !latest.Before(ceiling) {
		t.Fatalf("unlimited expiry %v exceeds the ClickHouse DateTime ceiling", latest)
	}
}

func TestResolveRetention_StampedDaysBecomeAWindow(t *testing.T) {
	t.Parallel()
	got, ok := Entitlements{Tier: "standard", RetentionDays: intPtr(30)}.ResolveRetention()
	if !ok {
		t.Fatal("expected a retention window")
	}
	if want := 30 * 24 * time.Hour; got != want {
		t.Fatalf("window = %v, want %v", got, want)
	}
}

// Retention must stay outside the stamped-limits trio: a gateway stamped before
// retention existed has to keep metering, not fail closed.
func TestRetentionDaysDoesNotCountAsAStampedLimit(t *testing.T) {
	t.Parallel()
	e := Entitlements{Tier: "free", RetentionDays: intPtr(7)}
	if e.HasStampedLimits() {
		t.Fatal("retention_days must not satisfy HasStampedLimits")
	}
	if _, ok := e.ResolveLimits(); ok {
		t.Fatal("retention_days must not resolve rate-limit caps")
	}
}

// A retention-only payload carries no rate-limit caps, so it must not trip the
// all-or-nothing stamp rule.
func TestNormalizeEntitlements_RetentionOnlyIsAccepted(t *testing.T) {
	t.Parallel()
	got, err := NormalizeEntitlements(Entitlements{Tier: "standard", RetentionDays: intPtr(30)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.RetentionDays == nil || *got.RetentionDays != 30 {
		t.Fatalf("retention_days = %v", got.RetentionDays)
	}
}

func TestNormalizeEntitlements_NegativeRetentionRejected(t *testing.T) {
	t.Parallel()
	_, err := NormalizeEntitlements(Entitlements{Tier: "free", RetentionDays: intPtr(-1)})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

// 0 is a legitimate stamp (unlimited), so validation must let it through.
func TestNormalizeEntitlements_ZeroRetentionAccepted(t *testing.T) {
	t.Parallel()
	got, err := NormalizeEntitlements(Entitlements{Tier: "enterprise", RetentionDays: intPtr(0)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.RetentionDays == nil || *got.RetentionDays != 0 {
		t.Fatalf("retention_days = %v, want 0", got.RetentionDays)
	}
}

func TestRequireStampedEntitlements_CarriesRetentionAlongsideCaps(t *testing.T) {
	t.Parallel()
	got, err := RequireStampedEntitlements(Entitlements{
		Tier:          "enterprise",
		BurstPerMin:   intPtr(1000),
		QuotaPerMonth: intPtr(0),
		MaxInstances:  intPtr(0),
		RetentionDays: intPtr(365),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.RetentionDays == nil || *got.RetentionDays != 365 {
		t.Fatalf("retention_days = %v", got.RetentionDays)
	}
}
