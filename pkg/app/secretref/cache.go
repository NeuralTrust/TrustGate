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

package secretref

import (
	"fmt"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// entry is one cached payload. Every field after the immutable header is
// guarded by Cache.mu.
type entry struct {
	payload   domain.Ref
	storeType secretstore.Type
	policy    secretstore.CachePolicy
	jitter    float64

	secret    secretstore.Secret
	hasValue  bool
	fetchedAt time.Time
	lastUsed  time.Time
	forcedAt  time.Time

	err     error
	retryAt time.Time
	backoff time.Duration
}

type lookupResult struct {
	secret    secretstore.Secret
	stale     bool
	refresh   bool
	needFetch bool
	err       error
}

func (e *entry) pinned() bool { return e.payload.Version != "" }

func (e *entry) expiresAt() time.Time { return e.fetchedAt.Add(e.policy.TTL) }

func (e *entry) deadAt() time.Time { return e.expiresAt().Add(e.policy.MaxStale) }

func (e *entry) refreshAt() time.Time {
	ratio := refreshAheadRatio + refreshJitterRatio*e.jitter
	return e.fetchedAt.Add(time.Duration(float64(e.policy.TTL) * ratio))
}

// lookup decides what a resolve gets from e at now. With mayFetch it may
// request a read. While a stale value can still be served the read happens in
// the background, so a slow or dead store never delays a caller that has a
// value; otherwise the caller waits for it.
func (e *entry) lookup(now time.Time, mayFetch bool) lookupResult {
	canRead := mayFetch && !now.Before(e.retryAt)
	if e.hasValue {
		if e.pinned() || now.Before(e.expiresAt()) {
			return lookupResult{secret: e.secret}
		}
		if now.Before(e.deadAt()) {
			return lookupResult{secret: e.secret, stale: true, refresh: canRead}
		}
		if canRead {
			return lookupResult{needFetch: true}
		}
		return lookupResult{err: e.deadErr()}
	}
	if canRead {
		return lookupResult{needFetch: true}
	}
	if e.err != nil {
		return lookupResult{err: e.err}
	}
	return lookupResult{err: fmt.Errorf("secret store %q: %w", e.payload.Store, secretstore.ErrUnavailable)}
}

func (e *entry) deadErr() error {
	if e.err != nil {
		return fmt.Errorf("last good value is older than max_stale: %w", e.err)
	}
	return fmt.Errorf("secret store %q: last good value is older than max_stale: %w", e.payload.Store, secretstore.ErrUnavailable)
}

// apply records the outcome of a fetch at now and reports whether dependents
// must be rebuilt: the value changed, appeared after a failure, or was
// withdrawn because the store denied it.
func (e *entry) apply(now time.Time, secret secretstore.Secret, err error) bool {
	if err == nil {
		changed := (e.hasValue && !e.secret.Equal(secret)) || (!e.hasValue && e.err != nil)
		e.secret, e.hasValue, e.fetchedAt = secret, true, now
		e.err, e.retryAt, e.backoff = nil, time.Time{}, 0
		return changed
	}
	e.err = err
	if secretstore.ServesStale(secretstore.ClassOf(err)) {
		e.backoff = nextBackoff(e.backoff, e.policy.TTL)
		e.retryAt = now.Add(e.backoff)
		return false
	}
	withdrawn := e.hasValue
	e.secret, e.hasValue = secretstore.Secret{}, false
	e.retryAt = now.Add(e.policy.NegativeTTL)
	e.backoff = 0
	return withdrawn
}

// expire withdraws a value whose stale window has closed, so dependents stop
// using it, and reports whether it did.
func (e *entry) expire(now time.Time) bool {
	if !e.hasValue || e.pinned() || now.Before(e.deadAt()) {
		return false
	}
	if e.err == nil {
		e.err = fmt.Errorf("secret store %q: %w", e.payload.Store, secretstore.ErrUnavailable)
	}
	e.secret, e.hasValue = secretstore.Secret{}, false
	return true
}

// due reports whether the refresher should read e again at now.
func (e *entry) due(now time.Time) bool {
	if now.Before(e.retryAt) {
		return false
	}
	if !e.hasValue {
		return true
	}
	return !e.pinned() && !now.Before(e.refreshAt())
}

func nextBackoff(current, ceiling time.Duration) time.Duration {
	next := current * 2
	if next < initialBackoff {
		next = initialBackoff
	}
	if next > ceiling {
		next = ceiling
	}
	return next
}
