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

import (
	"sync"
	"time"
)

type breaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
}

func newBreaker(threshold int, cooldown time.Duration) *breaker {
	if threshold < 1 {
		threshold = 1
	}
	return &breaker{threshold: threshold, cooldown: cooldown}
}

func (b *breaker) blockedUntil(now time.Time) (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Before(b.openUntil) {
		return b.openUntil, true
	}
	return time.Time{}, false
}

func (b *breaker) success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.openUntil = time.Time{}
}

func (b *breaker) failure(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = now.Add(b.cooldown)
		b.failures = b.threshold - 1
	}
}
