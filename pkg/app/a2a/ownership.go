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

package a2a

import (
	"context"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// Reasons of the -32092 answers ownership gives.
const (
	ReasonOwnershipUnavailable = "ownership_unavailable"
	ReasonOwnershipConflict    = "ownership_conflict"
)

// Reasons ownership records on the span only: the caller sees TaskNotFound,
// or its answer.
const (
	ReasonNotOwner             = "not_owner"
	ReasonNotRegistered        = "not_registered"
	ReasonOwnershipWriteFailed = "ownership_write_failed"
)

// ownershipTTL is how long a task or context stays bound to its owner after
// the last call that used it.
const ownershipTTL = 7 * 24 * time.Hour

// Ownership scopes: a task id or a context id.
const (
	ScopeTask    = "t"
	ScopeContext = "c"
)

// Owner is who a task or a context belongs to: a consumer and the subject of
// its principal.
type Owner struct {
	ConsumerID ids.ConsumerID `json:"consumer_id"`
	Subject    string         `json:"subject"`
	// UpstreamSession is the provider session a task or context runs in. It
	// is read only once the owner matched.
	UpstreamSession string `json:"upstream_session,omitempty"`
}

func (o *Owner) is(other Owner) bool {
	return o.ConsumerID == other.ConsumerID && o.Subject == other.Subject
}

// OwnershipKey names a task or a context of one agent.
type OwnershipKey struct {
	GatewayID  ids.GatewayID
	RegistryID ids.RegistryID
	Scope      string
	ID         string
}

// OwnershipStore keeps who owns each task and context.
type OwnershipStore interface {
	// Owner returns the owner of key, nil when it has none.
	Owner(ctx context.Context, key OwnershipKey) (*Owner, error)
	// Claim binds key to o unless it has an owner, and returns that owner
	// when it does.
	Claim(ctx context.Context, key OwnershipKey, o Owner, ttl time.Duration) (claimed bool, existing *Owner, err error)
	// Touch renews the binding of key.
	Touch(ctx context.Context, key OwnershipKey, ttl time.Duration) error
}

func (x *Exchange) ownershipKeys(c Content) []OwnershipKey {
	var keys []OwnershipKey
	for _, named := range [][2]string{{ScopeTask, c.TaskID}, {ScopeContext, c.ContextID}} {
		if named[1] != "" {
			keys = append(keys, OwnershipKey{GatewayID: x.call.Consumer.Consumer.GatewayID, RegistryID: x.call.Agent.ID, Scope: named[0], ID: named[1]})
		}
	}
	return keys
}

// checkOwner refuses a call that names a task or a context its caller does
// not own, whether another caller owns it or nobody does, so both look
// alike. A store that cannot be read fails the call.
func (x *Exchange) checkOwner(ctx context.Context) *RPCError {
	for _, key := range x.ownershipKeys(x.content) {
		owner, err := x.f.ownership.Owner(ctx, key)
		if err != nil {
			x.f.logger.WarnContext(ctx, "a2a ownership read failed", slog.String("registry_id", key.RegistryID.String()), slog.String("error", err.Error()))
			return GatewayFailure(ReasonOwnershipUnavailable)
		}
		if owner == nil {
			x.attrs.Reason = ReasonNotRegistered
			return TaskNotFound(x.version)
		}
		if !owner.is(x.owner) {
			x.attrs.Reason = ReasonNotOwner
			return TaskNotFound(x.version)
		}
		if owner.UpstreamSession != "" {
			x.session = owner.UpstreamSession
		}
	}
	return nil
}

// recordOwner binds the task and context an answer names to the caller, and
// renews them when the caller already owns them. An answer naming what
// another caller owns is a conflict and is not delivered. A store that
// cannot be written is logged and the answer is kept.
func (x *Exchange) recordOwner(ctx context.Context, c Content) *RPCError {
	for _, key := range x.ownershipKeys(c) {
		o := x.owner
		o.UpstreamSession = x.session
		claimed, existing, err := x.f.ownership.Claim(ctx, key, o, ownershipTTL)
		if err == nil && !claimed && existing != nil {
			if !existing.is(x.owner) {
				x.f.logger.WarnContext(ctx, "a2a agent answered with a task or context of another caller",
					slog.String("registry_id", key.RegistryID.String()), slog.String("scope", key.Scope))
				return GatewayFailure(ReasonOwnershipConflict)
			}
			err = x.f.ownership.Touch(ctx, key, ownershipTTL)
		}
		if err != nil {
			x.attrs.Reason = ReasonOwnershipWriteFailed
			x.f.logger.WarnContext(ctx, "a2a ownership write failed", slog.String("registry_id", key.RegistryID.String()), slog.String("error", err.Error()))
		}
	}
	return nil
}
