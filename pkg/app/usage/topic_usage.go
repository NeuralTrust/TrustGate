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

package usage

import (
	"context"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

var _ trafficlabels.UsageRecorder = (*TopicRecorder)(nil)

// TopicRecorder emits the topic classification record of a labeled request:
// the characters sent to the classifier, dated at the request's start.
type TopicRecorder struct {
	enabled  bool
	emitter  usagedomain.Emitter
	outcomes usagedomain.OutcomeRecorder
}

// NewTopicRecorder returns a recorder that emits through emitter when enabled
// is set and does nothing otherwise.
func NewTopicRecorder(enabled bool, emitter usagedomain.Emitter, outcomes usagedomain.OutcomeRecorder) *TopicRecorder {
	return &TopicRecorder{enabled: enabled && emitter != nil, emitter: emitter, outcomes: outcomes}
}

// Classified emits one record for a successful classifier call made for req.
func (r *TopicRecorder) Classified(ctx context.Context, req trafficlabel.Request, text string) {
	if r == nil || !r.enabled {
		return
	}
	chars := utf8.RuneCountInString(text)
	if chars == 0 {
		return
	}
	record, err := usagedomain.NewRecord(usagedomain.Record{
		EventID:                  usagedomain.TopicEventID(req.TraceID),
		TenantID:                 req.TenantID,
		OccurredOn:               req.ReceivedAt,
		TraceID:                  req.TraceID,
		GatewayID:                req.GatewayID,
		ConsumerID:               req.ConsumerID,
		TopicClassificationChars: int64(chars),
	})
	if err != nil {
		if r.outcomes != nil {
			r.outcomes.Outcome(usagedomain.OutcomeSkipped, 1)
		}
		return
	}
	r.emitter.Emit(ctx, record)
}
