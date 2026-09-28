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

package topicclassifier

import "time"

// Outcomes are the only label values the classifier's metrics carry, so the
// series stay bounded whatever the number of gateways. Per-gateway detail is
// in the topic_classification events themselves.
const (
	OutcomeAccepted      = "accepted"
	OutcomeBufferFull    = "buffer_full"
	OutcomeBodyTooLarge  = "body_too_large"
	OutcomeQueued        = "queued"
	OutcomeSampledOut    = "sampled_out"
	OutcomeNoText        = "no_text"
	OutcomeQuotaExceeded = "quota_exceeded"
	OutcomeQueueError    = "queue_error"
	OutcomeClassified    = "classified"
	OutcomeCacheHit      = "cache_hit"
	OutcomeFailed        = "failed"
	OutcomePoison        = "poison"
	OutcomeUnconfigured  = "unconfigured"
	OutcomeInvalid       = "invalid"
	OutcomeOK            = "ok"
	OutcomeError         = "error"
	OutcomeBackpressure  = "backpressure"
)

// Recorder receives the classifier's operational counts. Intake counts what
// the request path offered, Enqueue what reached the queue, Result how each
// queued request ended, and Call each topic-guard round trip.
//
//go:generate mockery --name=Recorder --dir=. --output=./mocks --filename=recorder_mock.go --case=underscore --with-expecter
type Recorder interface {
	Intake(outcome string)
	Enqueue(outcome string)
	Result(outcome string, n int)
	Call(outcome string, texts int, d time.Duration)
}

// NopRecorder records nothing.
type NopRecorder struct{}

func (NopRecorder) Intake(string)                   {}
func (NopRecorder) Enqueue(string)                  {}
func (NopRecorder) Result(string, int)              {}
func (NopRecorder) Call(string, int, time.Duration) {}

func orNop(r Recorder) Recorder {
	if r == nil {
		return NopRecorder{}
	}
	return r
}
