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

package mcp

import (
	"context"
	"sync"
)

// SubscriptionCaps bounds how many leases may be live at once, process-wide and
// per authorization identity.
type SubscriptionCaps struct {
	MaxStreams      int
	MaxPerConsumer  int
	MaxPerPrincipal int
}

// SubscriptionRegistry accounts live leases and owns their cancellation. It fans
// nothing out: no notification ever leaves the lease that produced it, so the
// registry holds capacity counters and lease contexts and nothing else.
type SubscriptionRegistry struct {
	mu           sync.Mutex
	caps         SubscriptionCaps
	total        int
	perConsumer  map[string]int
	perPrincipal map[string]int
	live         map[*SubscriptionLease]struct{}
	draining     bool
}

// NewSubscriptionRegistry builds a registry with the configured caps.
func NewSubscriptionRegistry(caps SubscriptionCaps) *SubscriptionRegistry {
	return &SubscriptionRegistry{
		caps:         caps,
		perConsumer:  make(map[string]int),
		perPrincipal: make(map[string]int),
		live:         make(map[*SubscriptionLease]struct{}),
	}
}

// Claim reserves capacity for one lease and returns it with a context cancelled
// by Release or by Drain. It returns ErrSubscriptionRefused when any cap is
// reached or the registry is draining, with no indication of which — the caps
// must not be usable as an occupancy oracle.
//
// All three counters are checked and incremented under one mutex so two
// concurrent listens cannot both pass the last slot.
func (r *SubscriptionRegistry) Claim(parent context.Context, key IsolationKey) (*SubscriptionLease, error) {
	if r == nil {
		return nil, ErrSubscriptionRefused
	}
	if parent == nil {
		parent = context.Background()
	}
	consumerBucket := key.ConsumerID
	principalBucket := key.Principal

	r.mu.Lock()
	if r.draining || !r.hasCapacity(consumerBucket, principalBucket) {
		r.mu.Unlock()
		return nil, ErrSubscriptionRefused
	}
	ctx, cancel := context.WithCancel(parent)
	lease := &SubscriptionLease{
		ctx:             ctx,
		cancel:          cancel,
		registry:        r,
		consumerBucket:  consumerBucket,
		principalBucket: principalBucket,
	}
	r.total++
	r.perConsumer[consumerBucket]++
	if principalBucket != "" {
		r.perPrincipal[principalBucket]++
	}
	r.live[lease] = struct{}{}
	r.mu.Unlock()
	return lease, nil
}

// hasCapacity reports whether every cap has room. A lease with no principal
// fingerprint is charged to its consumer only: there is no principal to bound,
// and folding it into a shared bucket would silently lower the consumer cap.
func (r *SubscriptionRegistry) hasCapacity(consumerBucket, principalBucket string) bool {
	if r.caps.MaxStreams > 0 && r.total >= r.caps.MaxStreams {
		return false
	}
	if r.caps.MaxPerConsumer > 0 && r.perConsumer[consumerBucket] >= r.caps.MaxPerConsumer {
		return false
	}
	if principalBucket == "" || r.caps.MaxPerPrincipal <= 0 {
		return true
	}
	return r.perPrincipal[principalBucket] < r.caps.MaxPerPrincipal
}

// Drain cancels and releases every live lease before returning. Registry
// capacity is reclaimed independently of body writers, which may remain blocked
// in a transport flush until the server write timeout.
func (r *SubscriptionRegistry) Drain(_ context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.draining = true
	leases := make([]*SubscriptionLease, 0, len(r.live))
	for lease := range r.live {
		leases = append(leases, lease)
	}
	r.mu.Unlock()

	for _, lease := range leases {
		lease.Release()
	}
	return nil
}

// Live is the number of leases currently accounted.
func (r *SubscriptionRegistry) Live() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

func (r *SubscriptionRegistry) release(lease *SubscriptionLease) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.live[lease]; !ok {
		return
	}
	delete(r.live, lease)
	r.total--
	if count := r.perConsumer[lease.consumerBucket] - 1; count > 0 {
		r.perConsumer[lease.consumerBucket] = count
	} else {
		delete(r.perConsumer, lease.consumerBucket)
	}
	if lease.principalBucket != "" {
		if count := r.perPrincipal[lease.principalBucket] - 1; count > 0 {
			r.perPrincipal[lease.principalBucket] = count
		} else {
			delete(r.perPrincipal, lease.principalBucket)
		}
	}
}

// SubscriptionLease is one accounted stream. Its context is the only
// cancellation signal the stream loop observes.
type SubscriptionLease struct {
	ctx             context.Context
	cancel          context.CancelFunc
	registry        *SubscriptionRegistry
	consumerBucket  string
	principalBucket string
	once            sync.Once
}

// Context is cancelled when the lease is released or drained.
func (l *SubscriptionLease) Context() context.Context {
	return l.ctx
}

// Release returns the lease's capacity and cancels its context. It is
// idempotent: a lease cancelled by Drain and then released by its own writer
// decrements exactly once.
func (l *SubscriptionLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.cancel()
		l.registry.release(l)
	})
}
