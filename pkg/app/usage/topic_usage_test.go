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

package usage_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

func labelRequest(tenant string) trafficlabel.Request {
	return trafficlabel.NewRequest(trafficlabel.RequestParams{
		GatewayID:  "gw-1",
		TenantID:   tenant,
		ConsumerID: "cons-1",
		TraceID:    "trace-1",
		Text:       "ignored: the recorder counts the text it is given",
		ReceivedAt: startTime,
	})
}

func TestTopicRecorder_CountsCodePointsAtTheRequestStart(t *testing.T) {
	t.Parallel()
	emitter := &captureEmitter{}
	rec := appusage.NewTopicRecorder(true, emitter, &outcomeCounter{})

	rec.Classified(context.Background(), labelRequest("tenant-1"), "¿Dónde está mi reembolso? 🧾")

	require.Len(t, emitter.records, 1)
	r := emitter.records[0]
	assert.Equal(t, "trustgate:trace-1:topic", r.EventID)
	assert.Equal(t, "trace-1", r.TraceID)
	assert.Equal(t, "tenant-1", r.TenantID)
	assert.Equal(t, "gw-1", r.GatewayID)
	assert.Equal(t, "cons-1", r.ConsumerID)
	assert.Equal(t, int64(27), r.TopicClassificationChars)
	assert.Zero(t, r.Requests)
	assert.Equal(t, time.Date(2026, 10, 20, 8, 5, 25, 123000000, time.UTC), r.OccurredOn)
}

func TestTopicRecorder_SkipsWhatItCannotBill(t *testing.T) {
	t.Parallel()
	emitter := &captureEmitter{}
	outcomes := &outcomeCounter{}
	rec := appusage.NewTopicRecorder(true, emitter, outcomes)

	rec.Classified(context.Background(), labelRequest(""), "text")
	rec.Classified(context.Background(), labelRequest("tenant-1"), "")

	assert.Empty(t, emitter.records)
	assert.Equal(t, 1, outcomes.counts[usagedomain.OutcomeSkipped], "a request without a tenant is counted as skipped")
}

func TestTopicRecorder_Disabled(t *testing.T) {
	t.Parallel()
	emitter := &captureEmitter{}
	appusage.NewTopicRecorder(false, emitter, nil).Classified(context.Background(), labelRequest("tenant-1"), "text")
	assert.Empty(t, emitter.records)
	var nilRecorder *appusage.TopicRecorder
	nilRecorder.Classified(context.Background(), labelRequest("tenant-1"), "text")
}
