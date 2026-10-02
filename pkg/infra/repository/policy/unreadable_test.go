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
		{
			name: "column the Go type rejects",
			row: rowFunc(func(dest ...any) error {
				*dest[0].(*ids.PolicyID) = id
				return errors.New("cannot scan NULL into *string")
			}),
			wantU: true,
		},
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
	skipped := reportUnreadable(context.Background(), "list", &UnreadablePolicyError{ID: id, Err: errors.New("boom")})
	if !skipped {
		t.Fatal("an unreadable row must be skipped")
	}
	out := buf.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "policy_id="+id.String()) {
		t.Fatalf("expected an ERROR log naming the policy id, got %q", out)
	}

	for _, err := range []error{errors.New("connection reset"), context.Canceled, pgx.ErrTxClosed} {
		if reportUnreadable(context.Background(), "list", err) {
			t.Fatalf("%v is not a row decode failure and must still fail the query", err)
		}
	}
}
