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

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBreaker(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	b := newBreaker(3, time.Minute)

	b.failure(now)
	b.failure(now)
	_, open := b.blockedUntil(now)
	assert.False(t, open, "below the threshold the breaker stays closed")

	b.failure(now)
	until, open := b.blockedUntil(now)
	assert.True(t, open)
	assert.Equal(t, now.Add(time.Minute), until)

	afterCooldown := now.Add(time.Minute + time.Second)
	_, open = b.blockedUntil(afterCooldown)
	assert.False(t, open, "the cooldown lets one attempt through")

	b.failure(afterCooldown)
	_, open = b.blockedUntil(afterCooldown)
	assert.True(t, open, "a failure right after the cooldown opens it again")

	b.success()
	_, open = b.blockedUntil(afterCooldown)
	assert.False(t, open, "a success closes it")
	b.failure(afterCooldown)
	_, open = b.blockedUntil(afterCooldown)
	assert.False(t, open, "and resets the count")
}

func TestBreakerThresholdFloor(t *testing.T) {
	t.Parallel()
	now := time.Now()
	b := newBreaker(0, time.Second)
	b.failure(now)
	_, open := b.blockedUntil(now)
	assert.True(t, open)
}
