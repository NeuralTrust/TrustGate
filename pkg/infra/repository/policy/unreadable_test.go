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

package policy

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// rowFunc adapts a function to rowScanner.
type rowFunc func(dest ...any) error

func (f rowFunc) Scan(dest ...any) error { return f(dest...) }

// fakeRow fills the destinations scanPolicy passes, in column order: 0 id, 9
// settings, 10 stages, 15 mcp_scope.
func fakeRow(id ids.PolicyID, settings, stages, scope string) rowFunc {
	return func(dest ...any) error {
		*dest[0].(*ids.PolicyID) = id
		*dest[9].(*[]byte) = []byte(settings)
		*dest[10].(*[]byte) = []byte(stages)
		*dest[11].(*time.Time) = time.Time{}
		*dest[15].(*[]byte) = []byte(scope)
		*dest[16].(*[]uuid.UUID) = nil
		return nil
	}
}

func TestScanPolicy_UnreadableRowCarriesTheID(t *testing.T) {
	id := ids.New[ids.PolicyKind]()
	tests := []struct {
		name  string
		row   rowScanner
		wantU bool
	}{
		{name: "settings is not an object", row: fakeRow(id, `[1,2]`, `[]`, ``), wantU: true},
		{name: "stages is not a list", row: fakeRow(id, `{}`, `{"a":1}`, ``), wantU: true},
		{name: "mcp_scope is not an object", row: fakeRow(id, `{}`, `[]`, `"x"`), wantU: true},
		{name: "readable row", row: fakeRow(id, `{"a":1}`, `["pre_request"]`, `{}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := scanPolicy(tt.row)
			if !tt.wantU {
				if err != nil || p == nil || p.ID != id {
					t.Fatalf("expected a readable policy, got %+v, %v", p, err)
				}
				return
			}
			var u *UnreadablePolicyError
			if !errors.As(err, &u) {
				t.Fatalf("expected *UnreadablePolicyError, got %v", err)
			}
			if u.ID != id {
				t.Fatalf("error lost the policy id: got %s want %s", u.ID, id)
			}
		})
	}
}

// A failure inside Scan itself is returned raw: pgx makes it fatal for the whole
// result set (and a single-row Scan does I/O), so it is never a skippable row.
func TestScanPolicy_ScanErrorsStayFatal(t *testing.T) {
	for _, scanErr := range []error{errors.New("cannot scan NULL into *string"), context.Canceled} {
		_, err := scanPolicy(rowFunc(func(...any) error { return scanErr }))
		if !errors.Is(err, scanErr) {
			t.Fatalf("expected the raw scan error, got %v", err)
		}
		var u *UnreadablePolicyError
		if errors.As(err, &u) {
			t.Fatalf("a Scan failure must not be reported as an unreadable row: %v", err)
		}
		if reportUnreadable(context.Background(), "list", err) {
			t.Fatalf("a Scan failure must still fail the query: %v", err)
		}
	}
}

func TestScanPolicy_NoRowsStaysNoRows(t *testing.T) {
	_, err := scanPolicy(rowFunc(func(...any) error { return pgx.ErrNoRows }))
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("FindByID maps ErrNoRows to not found; got %v", err)
	}
	var u *UnreadablePolicyError
	if errors.As(err, &u) {
		t.Fatalf("a missing row is not an unreadable one")
	}
}

func TestReportUnreadable(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	id := ids.New[ids.PolicyKind]()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prevMP := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() { otel.SetMeterProvider(prevMP); _ = mp.Shutdown(context.Background()) })

	gw := ids.New[ids.GatewayKind]()
	skipped := reportUnreadable(context.Background(), "list", &UnreadablePolicyError{ID: id, GatewayID: gw, Err: errors.New("boom")})
	if !skipped {
		t.Fatal("an unreadable row must be skipped")
	}
	out := buf.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "policy_id="+id.String()) {
		t.Fatalf("expected an ERROR log naming the policy id, got %q", out)
	}

	if !strings.Contains(out, "gateway_id="+gw.String()) {
		t.Fatalf("expected the gateway id in the log, got %q", out)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var count int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == "trustgate.policy.unreadable_rows" {
				for _, dp := range sum.DataPoints {
					count += dp.Value
				}
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected the unreadable_rows counter at 1, got %d", count)
	}

	for _, err := range []error{errors.New("connection reset"), context.Canceled, pgx.ErrTxClosed} {
		if reportUnreadable(context.Background(), "list", err) {
			t.Fatalf("%v is not a row decode failure and must still fail the query", err)
		}
	}
}
