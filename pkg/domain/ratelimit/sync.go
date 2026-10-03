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
	"fmt"
	"time"
)

// CounterKind names which plan counter a Bump belongs to.
type CounterKind string

const (
	KindQuota CounterKind = "quota"
	KindBurst CounterKind = "burst"
)

// Bump adds Delta to one counter window of a subject and asks for its new
// total. Window is "YYYY-MM" for the quota and the unix minute for the burst.
//
// A zero Delta is a read: it is how a pod learns what the rest of the tenant
// has spent without spending anything itself.
type Bump struct {
	Kind   CounterKind
	Window string
	Delta  int64
}

// SyncItem is everything one subject owes the shared counters on this tick.
//
// Token makes the item idempotent: the backend applies the bumps of a given
// token at most once and answers a repeat with the current totals. The sender
// reuses the same token, with the same bumps, when it cannot tell whether an
// attempt reached the backend (a timeout, a cancelled call). An empty token is
// for a pure read, which has nothing to apply twice.
type SyncItem struct {
	Subject string
	Token   string
	Bumps   []Bump
}

// SyncResult answers one SyncItem. Totals lines up with Bumps. Err is set when
// that item could not be applied; the others in the same batch still count.
type SyncResult struct {
	Totals []int64
	Err    error
}

const (
	// MaxFailedRetention is the longest a failed sync round may be retained.
	// Each retained round is one more item per pipeline on recovery, and one
	// more token key in Redis, so the bound keeps both small.
	MaxFailedRetention = 10 * time.Minute

	// TokenMargin is the slack kept between the last possible resend of a
	// retained round and the expiry of its token.
	TokenMargin = 5 * time.Second

	// MaxSyncTimeout caps RATE_LIMIT_SYNC_TIMEOUT. The retention check budgets
	// two calls of this length per round, so an unbounded timeout would either
	// make the check meaningless or force absurd retentions.
	MaxSyncTimeout = 5 * time.Second

	minTokenTTL = time.Minute
)

// TokenTTL is how long Redis remembers a sync token, derived from how long a
// failed round is retained: twice the retention, and never under a minute. A
// round is resent until its retention runs out, and the token must outlive its
// last resend, or a late retry would find no token and count the round twice.
// Every resend that finds the token pushes its expiry out by the full TTL again,
// so a round sent in several chunks, whose later chunks go out late, cannot lose
// its token between two sends; the TTL only has to cover the gap between sends.
func TokenTTL(retention time.Duration) time.Duration {
	ttl := 2 * retention
	if ttl < minTokenTTL {
		return minTokenTTL
	}
	return ttl
}

// ValidateRetention reports whether a retained round can never outlive its
// token. The last resend starts before retention + syncInterval (the first
// attempt past the retention is still sent). Two calls of up to syncTimeout
// each sit around that point: the first failing call, whose timeout runs before
// the failure is recorded and so before the retention clock starts, and the
// last resend itself. syncTimeout is capped at MaxSyncTimeout.
func ValidateRetention(retention, syncInterval, syncTimeout time.Duration) error {
	if retention > MaxFailedRetention {
		return fmt.Errorf("failed retention %s exceeds the maximum of %s", retention, MaxFailedRetention)
	}
	if syncTimeout > MaxSyncTimeout {
		return fmt.Errorf("sync timeout %s exceeds the maximum of %s", syncTimeout, MaxSyncTimeout)
	}
	worst := retention + syncInterval + 2*syncTimeout + TokenMargin
	if ttl := TokenTTL(retention); worst >= ttl {
		return fmt.Errorf("retention %s + sync interval %s + 2 x sync timeout %s + margin %s must stay under the token TTL %s",
			retention, syncInterval, syncTimeout, TokenMargin, ttl)
	}
	return nil
}
