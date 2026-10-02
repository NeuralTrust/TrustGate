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
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// UnreadablePolicyError reports a policies row whose content cannot be decoded.
// ID is the zero value when the failure hit the id column itself.
type UnreadablePolicyError struct {
	ID  ids.PolicyID
	Err error
}

func (e *UnreadablePolicyError) Error() string {
	return fmt.Sprintf("policy %s is unreadable: %v", e.ID, e.Err)
}

func (e *UnreadablePolicyError) Unwrap() error { return e.Err }

// reportUnreadable decides whether a scan failure inside a list loop may be
// skipped. It returns true only for an *UnreadablePolicyError, after logging it
// at ERROR with the policy id and counting it; every other error must still
// fail the query. One corrupt row must not discard the other policies of the
// query (a snapshot compiled without them leaves a gateway serving none), but it
// must never be silent either.
func reportUnreadable(ctx context.Context, operation string, err error) bool {
	var u *UnreadablePolicyError
	if !errors.As(err, &u) {
		return false
	}
	slog.ErrorContext(ctx, "policy repository: skipping unreadable policy row",
		slog.String("component", "policy_repository"),
		slog.String("operation", operation),
		slog.String("policy_id", u.ID.String()),
		slog.String("error", u.Err.Error()))
	recordUnreadable(ctx, operation)
	return true
}

// recordUnreadable counts a policy row skipped because it could not be read. The
// instrument is resolved on each call, as the SDK hands back the same one for
// the same name, and a skip is rare.
func recordUnreadable(ctx context.Context, operation string) {
	counter, err := otel.Meter("trustgate/policy_repository").Int64Counter(
		"trustgate.policy.unreadable_rows",
		metric.WithDescription("policy rows skipped from a list because their content could not be decoded"),
	)
	if err != nil {
		slog.WarnContext(ctx, "failed to create unreadable policy counter", slog.String("error", err.Error()))
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(attribute.String("operation", operation)))
}
