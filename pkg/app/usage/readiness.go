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
	"errors"
	"log/slog"
	"sync"
	"time"
)

// ErrListNotReady is reported while a plane waits for its first usage list.
var ErrListNotReady = errors.New("usage: no usage list yet")

// ReadinessCheck keeps a plane not ready while ready reports false, so a new
// pod does not serve exhausted tenants as if nobody were. The wait is counted
// from the first probe that finds the plane not ready, not from boot, so a
// data plane that only learns later that usage is enforced still waits. After
// timeout it gives up and reports ready, logging an error once per wait: an
// unreachable Usage System or cache must not stall every rollout.
func ReadinessCheck(ready func() bool, timeout time.Duration, logger *slog.Logger) func(context.Context) error {
	if logger == nil {
		logger = slog.Default()
	}
	var mu sync.Mutex
	var waitingSince time.Time
	var gaveUp bool
	return func(ctx context.Context) error {
		isReady := ready()
		mu.Lock()
		if isReady {
			waitingSince, gaveUp = time.Time{}, false
			mu.Unlock()
			return nil
		}
		if waitingSince.IsZero() {
			waitingSince = time.Now()
		}
		if time.Since(waitingSince) < timeout {
			mu.Unlock()
			return ErrListNotReady
		}
		logGiveUp := !gaveUp
		gaveUp = true
		mu.Unlock()
		if logGiveUp {
			logger.ErrorContext(ctx, "usage: serving without a usage list; exhausted tenants are not blocked until it arrives",
				slog.Duration("waited", timeout))
		}
		return nil
	}
}
