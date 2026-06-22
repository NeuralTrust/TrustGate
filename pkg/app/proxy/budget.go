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

package proxy

import (
	"time"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

type failoverBudget struct {
	maxAttempts int
	deadline    time.Time
	attempts    int
}

func newFailoverBudget(fb *consumerdomain.Fallback) *failoverBudget {
	b := &failoverBudget{}
	if fb == nil || !fb.Enabled {
		return b
	}
	if fb.Budget.MaxAttempts > 0 {
		b.maxAttempts = fb.Budget.MaxAttempts
	}
	if fb.Budget.MaxTotalLatency > 0 {
		b.deadline = time.Now().Add(fb.Budget.MaxTotalLatency)
	}
	return b
}

func (b *failoverBudget) recordAttempt() {
	b.attempts++
}

func (b *failoverBudget) exhausted() bool {
	if b.maxAttempts > 0 && b.attempts >= b.maxAttempts {
		return true
	}
	if b.attempts > 0 && !b.deadline.IsZero() && time.Now().After(b.deadline) {
		return true
	}
	return false
}
