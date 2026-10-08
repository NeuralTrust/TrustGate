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

package auth

import (
	"context"
	"log/slog"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// PersonalKeyExpiryMargin keeps a new key's expiry clear of the 90-day
// ceiling, so a request that takes a moment to arrive is not refused for
// asking for the very limit. The console's Portal uses the same margin.
const PersonalKeyExpiryMargin = 5 * time.Minute

// PersonalKeyIssuer gives a person their personal key from outside the
// console: the MCP Store's personal key page. It is PersonalKeys with the
// Portal's rules applied and the owner's groups recorded on a new key, so the
// key opens the Store with them from the first call rather than once the
// console's reconcile catches up.
//
// On a data plane with no database it is served by the control plane over
// config sync; see the PersonalKeys gRPC service.
type PersonalKeyIssuer interface {
	// Get is the owner's key, or domain.ErrNotFound.
	Get(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*PersonalKey, error)
	// Create issues the owner's key for as long as a personal key may live,
	// with groups as its owner groups. The secret is on the returned key, once.
	Create(ctx context.Context, gatewayID ids.GatewayID, ownerID string, groups []string) (*PersonalKey, error)
	// Rotate replaces the secret, keeping the key's id and links. An expired
	// key is given a new full lifetime with it; otherwise its expiry stays.
	Rotate(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*PersonalKey, error)
	// Revoke deletes the owner's key, or answers domain.ErrNotFound.
	Revoke(ctx context.Context, gatewayID ids.GatewayID, ownerID string) error
}

// PersonalKeyEventKind is what happened to a personal key.
type PersonalKeyEventKind string

const (
	PersonalKeyCreated PersonalKeyEventKind = "created"
	PersonalKeyRotated PersonalKeyEventKind = "rotated"
	PersonalKeyRevoked PersonalKeyEventKind = "revoked"
)

// PersonalKeyEvent is a change made to a personal key outside the console,
// told to the console so it does what it does when the Portal makes it: audit
// it, and reconcile the key's links (a new key reaches no model until then).
type PersonalKeyEvent struct {
	Kind      PersonalKeyEventKind
	GatewayID ids.GatewayID
	TenantID  string
	OwnerID   string
	AuthID    ids.AuthID
	ExpiresAt *time.Time
	// Renewed: a rotation that gave an expired key a new lifetime.
	Renewed bool
}

// PersonalKeyNotifier tells the console about a change. It is best effort: the
// change is made, and a console that misses it reconciles on its next pass.
type PersonalKeyNotifier interface {
	Notify(ctx context.Context, event PersonalKeyEvent) error
}

// GatewayFinder resolves a gateway, for the tenant an event is told to.
type GatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

// personalKeyNotifyTimeout bounds the call to the console, which is made after
// the page has its answer.
const personalKeyNotifyTimeout = 10 * time.Second

var _ PersonalKeyIssuer = (*personalKeyIssuer)(nil)

type personalKeyIssuer struct {
	keys     PersonalKeys
	groups   OwnerGroupsSetter
	gateways GatewayFinder
	notifier PersonalKeyNotifier
	logger   *slog.Logger
	now      func() time.Time
}

// PersonalKeyIssuerOption configures the issuer.
type PersonalKeyIssuerOption func(*personalKeyIssuer)

// WithPersonalKeyNotifier tells the console about every change, resolving the
// gateway's tenant through gateways.
func WithPersonalKeyNotifier(notifier PersonalKeyNotifier, gateways GatewayFinder) PersonalKeyIssuerOption {
	return func(i *personalKeyIssuer) {
		i.notifier = notifier
		i.gateways = gateways
	}
}

// NewPersonalKeyIssuer returns the issuer over the control plane's own
// PersonalKeys and OwnerGroupsSetter.
func NewPersonalKeyIssuer(keys PersonalKeys, groups OwnerGroupsSetter, logger *slog.Logger, now func() time.Time, opts ...PersonalKeyIssuerOption) PersonalKeyIssuer {
	if logger == nil {
		logger = slog.Default()
	}
	i := &personalKeyIssuer{keys: keys, groups: groups, logger: logger, now: utcClock(now)}
	for _, opt := range opts {
		if opt != nil {
			opt(i)
		}
	}
	return i
}

func (i *personalKeyIssuer) Get(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*PersonalKey, error) {
	return i.keys.Get(ctx, gatewayID, ownerID)
}

func (i *personalKeyIssuer) Create(ctx context.Context, gatewayID ids.GatewayID, ownerID string, groups []string) (*PersonalKey, error) {
	key, err := i.keys.Create(ctx, gatewayID, ownerID, i.fullLifetime())
	if err != nil {
		return nil, err
	}
	i.notify(ctx, PersonalKeyEvent{Kind: PersonalKeyCreated, GatewayID: gatewayID, OwnerID: ownerID, AuthID: key.Auth.ID, ExpiresAt: key.Auth.ExpiresAt})
	normalized, err := domain.NormalizeOwnerGroups(groups)
	if err != nil || len(normalized) == 0 || i.groups == nil {
		return key, nil
	}
	// The key exists and its secret is about to be shown once: failing here
	// would leave the person a key they never saw. Without its groups it still
	// opens the Store, narrowed to what names them alone, until the console's
	// reconcile records the groups.
	updated, err := i.groups.SetOwnerGroups(ctx, SetOwnerGroupsInput{ID: key.Auth.ID, GatewayID: gatewayID, Groups: normalized})
	if err != nil {
		i.logger.WarnContext(ctx, "personal key: record owner groups",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("auth_id", key.Auth.ID.String()),
			slog.String("error", err.Error()))
		return key, nil
	}
	key.Auth.OwnerGroups = updated.OwnerGroups
	return key, nil
}

func (i *personalKeyIssuer) Rotate(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*PersonalKey, error) {
	current, err := i.keys.Get(ctx, gatewayID, ownerID)
	if err != nil {
		return nil, err
	}
	var expiresAt *time.Time
	if current.Auth.IsExpired(i.now()) {
		renewed := i.fullLifetime()
		expiresAt = &renewed
	}
	rotated, err := i.keys.Rotate(ctx, gatewayID, ownerID, expiresAt)
	if err != nil {
		return nil, err
	}
	i.notify(ctx, PersonalKeyEvent{Kind: PersonalKeyRotated, GatewayID: gatewayID, OwnerID: ownerID, AuthID: rotated.Auth.ID, ExpiresAt: rotated.Auth.ExpiresAt, Renewed: expiresAt != nil})
	return rotated, nil
}

func (i *personalKeyIssuer) Revoke(ctx context.Context, gatewayID ids.GatewayID, ownerID string) error {
	current, err := i.keys.Get(ctx, gatewayID, ownerID)
	if err != nil {
		return err
	}
	if err := i.keys.Revoke(ctx, gatewayID, ownerID); err != nil {
		return err
	}
	i.notify(ctx, PersonalKeyEvent{Kind: PersonalKeyRevoked, GatewayID: gatewayID, OwnerID: ownerID, AuthID: current.Auth.ID})
	return nil
}

// notify tells the console in the background: the page has its answer, and
// the console's own reconcile covers a notice that never arrives.
func (i *personalKeyIssuer) notify(ctx context.Context, event PersonalKeyEvent) {
	if i.notifier == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), personalKeyNotifyTimeout)
		defer cancel()
		if i.gateways != nil {
			if gw, err := i.gateways.FindByID(ctx, event.GatewayID); err == nil && gw != nil {
				event.TenantID = gw.TenantID()
			}
		}
		if err := i.notifier.Notify(ctx, event); err != nil {
			i.logger.WarnContext(ctx, "personal key: tell the console",
				slog.String("event", string(event.Kind)),
				slog.String("gateway_id", event.GatewayID.String()),
				slog.String("auth_id", event.AuthID.String()),
				slog.String("error", err.Error()))
		}
	}()
}

func (i *personalKeyIssuer) fullLifetime() time.Time {
	return i.now().Add(domain.MaxOwnedKeyLifetime - PersonalKeyExpiryMargin).Truncate(time.Second)
}
