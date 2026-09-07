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

package trustguard

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	failureReasonUnauthorized = "unauthorized"
	failureReasonTransport    = "transport"
)

var (
	evaluateFailuresOnce sync.Once
	evaluateFailures     metric.Int64Counter
)

func recordEvaluateFailure(ctx context.Context, reason string) {
	evaluateFailuresOnce.Do(func() {
		c, err := otel.Meter("trustgate/trustguard").Int64Counter(
			"trustguard_evaluate_failures_total",
			metric.WithDescription("TrustGuard /v1/evaluate call failures by reason"),
		)
		if err != nil {
			return
		}
		evaluateFailures = c
	})
	if evaluateFailures == nil {
		return
	}
	evaluateFailures.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}
