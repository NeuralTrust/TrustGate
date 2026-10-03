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

package trafficlabels

import "time"

const (
	OutcomeAccepted      = "accepted"
	OutcomeBufferFull    = "buffer_full"
	OutcomeShuttingDown  = "shutting_down"
	OutcomeBodyTooLarge  = "body_too_large"
	OutcomeSampledOut    = "sampled_out"
	OutcomeQueued        = "queued"
	OutcomeNoText        = "no_text"
	OutcomeQuotaExceeded = "quota_exceeded"
	OutcomeQueueError    = "queue_error"
	OutcomeClassified    = "classified"
	OutcomeCacheHit      = "cache_hit"
	OutcomeFailed        = "failed"
	OutcomePoison        = "poison"
	OutcomeUnconfigured  = "unconfigured"
	OutcomeInvalid       = "invalid"
	OutcomeUnpublishable = "unpublishable"
	OutcomePublishRetry  = "publish_retry"
	OutcomeOK            = "ok"
	OutcomeError         = "error"
	OutcomeBackpressure  = "backpressure"
)

func Outcomes() []string {
	return []string{
		OutcomeAccepted, OutcomeBufferFull, OutcomeShuttingDown, OutcomeBodyTooLarge,
		OutcomeSampledOut, OutcomeQueued, OutcomeNoText, OutcomeQuotaExceeded,
		OutcomeQueueError, OutcomeClassified, OutcomeCacheHit, OutcomeFailed,
		OutcomePoison, OutcomeUnconfigured, OutcomeInvalid, OutcomeUnpublishable,
		OutcomePublishRetry, OutcomeOK, OutcomeError, OutcomeBackpressure,
	}
}

//go:generate mockery --name=Recorder --dir=. --output=./mocks --filename=recorder_mock.go --case=underscore --with-expecter
//go:generate mockery --name=Recorder --dir=. --output=. --inpackage --testonly --filename=recorder_mock_test.go --case=underscore --with-expecter
type Recorder interface {
	Intake(outcome string)
	Enqueue(outcome string)
	Result(outcome string, n int)
	Call(outcome string, d time.Duration)
}
