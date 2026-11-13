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

package secretstore

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// Caller is what the admin API knows about whoever writes a reference.
type Caller struct {
	// MayReference is false for a service credential without the
	// secret_stores:read scope. Console users always may: the console's own
	// roles authorize them.
	MayReference bool
	// AllowUnverified is the allow_unverified_secret_refs opt-in.
	AllowUnverified bool
	// Actor names the caller in the audit event.
	Actor string
}

type callerKey struct{}

// WithCaller attaches the caller to ctx for the validator.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

func callerFrom(ctx context.Context) Caller {
	c, _ := ctx.Value(callerKey{}).(Caller)
	return c
}

// GatewayReader reads the gateway a registry belongs to.
type GatewayReader interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gateway.Gateway, error)
}

//go:generate mockery --name=RegistryValidator --dir=. --output=./mocks --filename=secretstore_registry_validator_mock.go --case=underscore --with-expecter

// RegistryValidator checks the secret references a registry write holds.
type RegistryValidator interface {
	// ValidateRegistry checks the reference-shaped values of reg that are
	// not already stored at the same field of previous (what the registry
	// held before the write, nil on create), so a client echoing a stored
	// value back is never refused. When the write changes where the registry
	// sends its credentials, every reference it holds is checked again, as
	// if newly set: the stored value would otherwise reach the new host
	// without the caller's scope being checked. For those values it checks, in
	// order: every value is a whole reference that
	// parses, the gateway is eligible, the caller may reference, and every
	// reference names a store of the gateway's store source that allows its
	// path. On success it returns the audit to record once the write is
	// saved: every reference set, changed or removed.
	ValidateRegistry(ctx context.Context, reg *registry.Registry, previous *appsecretref.Stored) (func(), error)
	// ValidateEntity applies the same checks to the declared locations of any
	// entity: current is what the write holds, previous what was stored.
	ValidateEntity(ctx context.Context, current EntityRefs, previous *appsecretref.Stored) (func(), error)
}

// EntityRefs is what one write of an entity holds at its declared locations.
type EntityRefs struct {
	GatewayID ids.GatewayID
	Entity    refdomain.Entity
	ID        string
	Uses      []appsecretref.Use
	Embedded  []appsecretref.Use
	// Destination fingerprints where the entity sends its credentials; a
	// change re-checks every reference it holds.
	Destination string
}

type registryValidator struct {
	sources  SourceResolver
	gateways GatewayReader
	logger   *slog.Logger
}

// NewRegistryValidator returns a RegistryValidator.
func NewRegistryValidator(sources SourceResolver, gateways GatewayReader, logger *slog.Logger) RegistryValidator {
	if logger == nil {
		logger = slog.Default()
	}
	return &registryValidator{sources: sources, gateways: gateways, logger: logger}
}

type parsedUse struct {
	path string
	ref  refdomain.Ref
}

func (v *registryValidator) ValidateRegistry(ctx context.Context, reg *registry.Registry, stored *appsecretref.Stored) (func(), error) {
	uses, embedded := appsecretref.RegistryReferences(reg)
	return v.ValidateEntity(ctx, EntityRefs{
		GatewayID: reg.GatewayID, Entity: refdomain.EntityRegistry, ID: reg.ID.String(),
		Uses: uses, Embedded: embedded, Destination: appsecretref.RegistryDestination(reg),
	}, stored)
}

// ValidateEntity implements RegistryValidator.
func (v *registryValidator) ValidateEntity(ctx context.Context, current EntityRefs, stored *appsecretref.Stored) (func(), error) {
	var previous []appsecretref.Use
	if stored != nil {
		previous = stored.Uses
	}
	uses := changedUses(current.Uses, previous)
	if stored != nil && stored.Destination != current.Destination {
		uses = current.Uses
	}
	removed := removedUses(previous, current.Uses)
	audit := func() { v.audit(ctx, current, uses, removed) }
	if embedded := changedUses(current.Embedded, previous); len(embedded) > 0 {
		return nil, embeddedError(embedded)
	}
	if len(uses) == 0 {
		return audit, nil
	}
	parsed := make([]parsedUse, 0, len(uses))
	for _, u := range uses {
		ref, _, err := refdomain.Parse(u.Raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", strings.Join(u.Path, "."), err)
		}
		parsed = append(parsed, parsedUse{path: strings.Join(u.Path, "."), ref: ref})
	}

	gw, err := v.gateways.FindByID(ctx, current.GatewayID)
	if err != nil {
		return nil, err
	}
	src, err := v.sources.Source(ctx, gw)
	if err != nil {
		return nil, err
	}
	if !src.Supported {
		return nil, refdomain.ErrReferencesNotSupported
	}
	caller := callerFrom(ctx)
	if !caller.MayReference {
		return nil, refdomain.ErrMissingScope
	}
	if err := checkSource(src, parsed, caller); err != nil {
		return nil, err
	}
	unverified := src.Kind == KindDataPlane && src.Live == 0
	return func() {
		if unverified {
			v.logger.Warn("secret references saved without a connected data plane to verify the store",
				slog.String("gateway_id", current.GatewayID.String()), slog.String("entity", string(current.Entity)), slog.String("id", current.ID))
		}
		audit()
	}, nil
}

func embeddedError(embedded []appsecretref.Use) error {
	return fmt.Errorf("%w: %s holds a reference inside a longer value; a reference must be the whole value",
		refdomain.ErrInvalidReference, strings.Join(embedded[0].Path, "."))
}

// audit logs secret_reference_set for every reference a saved write set,
// changed or removed: what changed and who changed it, never a value.
func (v *registryValidator) audit(ctx context.Context, current EntityRefs, set, removed []appsecretref.Use) {
	actor := callerFrom(ctx).Actor
	log := func(u appsecretref.Use, action string) {
		attrs := []any{
			slog.String("gateway_id", current.GatewayID.String()),
			slog.String("entity", string(current.Entity)),
			slog.String("id", current.ID),
			slog.String("field", strings.Join(u.Path, ".")),
			slog.String("action", action),
			slog.String("actor", actor),
		}
		if ref, ok, err := refdomain.Parse(u.Raw); ok && err == nil {
			attrs = append(attrs, slog.String("store", ref.Store), slog.String("path", ref.Path))
		}
		v.logger.Info("secret_reference_set", attrs...)
	}
	for _, u := range set {
		log(u, "set")
	}
	for _, u := range removed {
		log(u, "removed")
	}
}

// removedUses lists the stored references whose field no longer holds one.
func removedUses(previous, current []appsecretref.Use) []appsecretref.Use {
	now := make(map[string]bool, len(current))
	for _, u := range current {
		now[strings.Join(u.Path, "\x00")] = true
	}
	var out []appsecretref.Use
	for _, p := range previous {
		if refdomain.IsRef(p.Raw) && !now[strings.Join(p.Path, "\x00")] {
			out = append(out, p)
		}
	}
	return out
}

// changedUses drops the uses whose field already held the same value.
func changedUses(uses, previous []appsecretref.Use) []appsecretref.Use {
	if len(previous) == 0 {
		return uses
	}
	stored := make(map[string]string, len(previous))
	for _, p := range previous {
		stored[strings.Join(p.Path, "\x00")] = p.Raw
	}
	out := uses[:0:0]
	for _, u := range uses {
		if raw, ok := stored[strings.Join(u.Path, "\x00")]; ok && raw == u.Raw {
			continue
		}
		out = append(out, u)
	}
	return out
}

func checkSource(src Source, parsed []parsedUse, caller Caller) error {
	if src.Kind == KindDataPlane {
		if src.Live == 0 {
			if caller.AllowUnverified {
				return nil
			}
			return refdomain.ErrStoreUnverified
		}
		if len(src.TooOld) > 0 {
			return fmt.Errorf("%w (instance %s)", refdomain.ErrDataPlaneTooOld, src.TooOld[0].InstanceID)
		}
	}
	for _, p := range parsed {
		store, ok := src.Store(p.ref.Store)
		if !ok {
			return fmt.Errorf("%w: %q (%s)", refdomain.ErrUnknownStore, p.ref.Store, p.path)
		}
		if !store.AllowsPath(p.ref.Path) {
			return fmt.Errorf("%w: %s (%s)", refdomain.ErrPathNotAllowed, p.ref.Path, p.path)
		}
		if p.ref.Version != "" && (store.Type == domain.TypeFile || store.Type == domain.TypeEnv) {
			return fmt.Errorf("%w: %s stores have no versions (%s)", refdomain.ErrInvalidReference, store.Type, p.path)
		}
	}
	return nil
}
