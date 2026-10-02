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
	"testing"
	"time"
)

func TestTokenTTLFollowsRetention(t *testing.T) {
	cases := []struct {
		retention, want time.Duration
	}{
		{0, time.Minute},
		{10 * time.Second, time.Minute},
		{30 * time.Second, time.Minute},
		{45 * time.Second, 90 * time.Second},
		{5 * time.Minute, 10 * time.Minute},
		{MaxFailedRetention, 20 * time.Minute},
	}
	for _, c := range cases {
		if got := TokenTTL(c.retention); got != c.want {
			t.Errorf("TokenTTL(%s) = %s, want %s", c.retention, got, c.want)
		}
	}
}

func TestValidateRetention(t *testing.T) {
	cases := []struct {
		name                         string
		retention, interval, timeout time.Duration
		wantErr                      bool
	}{
		{"defaults", 30 * time.Second, time.Second, 200 * time.Millisecond, false},
		{"upper bound", MaxFailedRetention, time.Second, 200 * time.Millisecond, false},
		{"over the bound", MaxFailedRetention + time.Second, time.Second, 200 * time.Millisecond, true},
		{"slow sync outlives the minimum TTL", 30 * time.Second, 20 * time.Second, 10 * time.Second, true},
		{"timeout over the cap", time.Second, time.Second, MaxSyncTimeout + time.Millisecond, true},
		{"timeout at the cap", time.Second, time.Second, MaxSyncTimeout, false},
		{"two timeouts outlive it, one would not", 25 * time.Second, 20 * time.Second, 5 * time.Second, true},
		{"two timeouts just fit", 25 * time.Second, 19 * time.Second, 5 * time.Second, false},
	}
	for _, c := range cases {
		err := ValidateRetention(c.retention, c.interval, c.timeout)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}
