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

package ratelimit

import (
	"context"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func captureSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	return rec
}

func spanAttr(attrs []attribute.KeyValue, key string) (attribute.Value, bool) {
	for _, kv := range attrs {
		if string(kv.Key) == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

// Every sync round that has work is one ratelimit.sync span, carrying how many
// tenants it covered; a round with nothing to do emits none, so an idle pod does
// not fill the trace backend. The request path starts no span of its own.
func TestSyncEmitsOneSpanPerRoundWithWork(t *testing.T) {
	rec := captureSpans(t)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	m := testMeter(r, newBackend(newShared()), newClock(midMonth), nil)

	require.NoError(t, m.SyncNow(bg))
	assert.Empty(t, rec.Ended(), "no tenant, no round, no span")

	require.NoError(t, m.Check(bg, id))
	assert.Empty(t, rec.Ended(), "a request starts no span: it does no I/O")
	require.NoError(t, m.SyncNow(bg))

	spans := rec.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "ratelimit.sync", spans[0].Name())
	tenants, ok := spanAttr(spans[0].Attributes(), "ratelimit.tenants")
	require.True(t, ok)
	assert.EqualValues(t, 1, tenants.AsInt64())
	failed, _ := spanAttr(spans[0].Attributes(), "ratelimit.failed")
	assert.False(t, failed.AsBool())
	assert.Equal(t, codes.Unset, spans[0].Status().Code)
}

func TestFailedSyncMarksItsSpanAsAnError(t *testing.T) {
	rec := captureSpans(t)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	backend := newBackend(newShared())
	backend.fail.Store(true)
	m := testMeter(r, backend, newClock(midMonth), nil)

	require.NoError(t, m.Check(bg, id))
	require.Error(t, m.SyncNow(bg))

	spans := rec.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status().Code)
	failed, _ := spanAttr(spans[0].Attributes(), "ratelimit.failed")
	assert.True(t, failed.AsBool())
	outage, _ := spanAttr(spans[0].Attributes(), "ratelimit.outage")
	assert.True(t, outage.AsBool(), "a failed call is an outage, not one tenant's problem")
}
