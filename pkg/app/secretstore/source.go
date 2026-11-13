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

// Package secretstore is the admin side of secret stores: which stores a
// gateway may reference, where they are reported from, and whether a write
// that holds references may be saved.
package secretstore

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// Kind is where a gateway's stores are configured and reported from.
type Kind string

// Store sources.
const (
	// KindDataPlane: the gateway is served by data planes of its own, which
	// report their stores in the heartbeat.
	KindDataPlane Kind = "data_plane"
	// KindControlPlane: the gateway is served by the control plane's own
	// cluster, whose admin loads the same store file.
	KindControlPlane Kind = "control_plane"
)

// Aggregated store status across the instances that report it.
const (
	StatusOK          = "ok"
	StatusDegraded    = "degraded"
	StatusDown        = "down"
	StatusNotReported = "not_reported"
)

// InstanceStateTooOld marks a live data plane that does not understand
// secret references.
const InstanceStateTooOld = "too_old"

// InstanceView is what one plane reported about a store.
type InstanceView struct {
	InstanceID string
	Version    string
	State      string
	ErrorClass string
	CheckedAt  time.Time
}

// StoreView is one store a gateway may reference.
type StoreView struct {
	Name         string
	Type         domain.Type
	AllowedPaths []string
	// AllowedDestinations is the store's host allowlist; nil allows any
	// host.
	AllowedDestinations []string
	Status              string
	// Consistent is false when instances disagree on the store's type,
	// allowed paths, allowed destinations or allowlist.
	Consistent bool
	Instances  []InstanceView
	// instancePaths holds each reporting instance's allowed paths, which
	// differ from AllowedPaths when the store is not Consistent.
	instancePaths [][]string
	// instanceDestinations is instancePaths for allowed destinations.
	instanceDestinations [][]string
}

// Source is a gateway's store source.
type Source struct {
	Supported bool
	Kind      Kind
	// Live counts the live data planes of a KindDataPlane source.
	Live int
	// TooOld lists live data planes that do not understand references.
	TooOld []InstanceView
	Stores []StoreView
	// refs is what each live instance, or the admin, last reported about
	// the references it resolved.
	refs []domain.RefHealth
}

// Usage states.
const (
	RefStateOK          = "ok"
	RefStateFailing     = "failing"
	RefStateNotReported = "not_reported"
)

// Annotate sets the State and ErrorClass of every usage of gw.
func (s Source) Annotate(gw ids.GatewayID, usages map[string][]Usage) {
	for _, list := range usages {
		for i := range list {
			state, class := s.RefState(gw, list[i])
			list[i].State, list[i].ErrorClass = state, string(class)
		}
	}
}

// RefState returns the state of usage u of gateway gw: failing, with the
// class, when any reporter left it unresolved; ok when one resolved it;
// not_reported otherwise, as for a reference no plane has resolved since it
// was written.
func (s Source) RefState(gw ids.GatewayID, u Usage) (state string, class domain.Class) {
	ref, _, err := refdomain.Parse(u.Reference)
	if err != nil {
		return RefStateNotReported, ""
	}
	state = RefStateNotReported
	for _, h := range s.refs {
		o, ok := h.Find(gw, u.Entity, u.ID, u.Field, ref.String())
		if !ok {
			continue
		}
		if o.Class != "" {
			return RefStateFailing, o.Class
		}
		state = RefStateOK
	}
	return state, ""
}

// Store returns the store named name, if the source has it.
func (s Source) Store(name string) (StoreView, bool) {
	for _, st := range s.Stores {
		if st.Name == name {
			return st, true
		}
	}
	return StoreView{}, false
}

// InstanceLister reads the data-plane instances recorded for a scope.
type InstanceLister interface {
	ListInstances(ctx context.Context, scope string) ([]dataplane.Instance, error)
}

// StoreHealth reports the stores the admin itself loaded.
type StoreHealth interface {
	Statuses() []domain.Status
}

//go:generate mockery --name=SourceResolver --dir=. --output=./mocks --filename=secretstore_source_resolver_mock.go --case=underscore --with-expecter

// SourceResolver derives a gateway's store source.
type SourceResolver interface {
	Source(ctx context.Context, gw *gateway.Gateway) (Source, error)
}

// SourceConfig configures NewSourceResolver.
type SourceConfig struct {
	Eligibility domain.Eligibility
	// Health is the admin's own catalog; nil when the admin loads no store
	// file, as on NeuralTrust's control plane.
	Health StoreHealth
	// RefHealth is what the admin observed about the references it resolved
	// itself; nil when it loads no store file.
	RefHealth func() domain.RefHealth
	Instances InstanceLister
	// AdminInstance names the admin replica in a control_plane listing.
	AdminInstance string
	Now           func() time.Time
}

type sourceResolver struct {
	cfg SourceConfig
}

// NewSourceResolver returns a SourceResolver.
func NewSourceResolver(cfg SourceConfig) SourceResolver {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &sourceResolver{cfg: cfg}
}

// Source implements SourceResolver. A gateway served by data planes of its
// own takes the union of what its live instances report; any other gateway
// takes the admin's own catalog. Stores whose allowlist excludes the gateway
// are left out.
func (r *sourceResolver) Source(ctx context.Context, gw *gateway.Gateway) (Source, error) {
	own := gw.ServedByOwnDataPlane()
	supported := domain.Eligible(r.cfg.Eligibility, gw) && (own || r.cfg.Health != nil)
	if !supported {
		return Source{}, nil
	}
	if !own {
		src := Source{Supported: true, Kind: KindControlPlane, Stores: r.adminStores(gw.ID)}
		if r.cfg.RefHealth != nil {
			src.refs = []domain.RefHealth{r.cfg.RefHealth()}
		}
		return src, nil
	}
	if r.cfg.Instances == nil {
		return Source{Supported: true, Kind: KindDataPlane}, nil
	}
	instances, err := r.cfg.Instances.ListInstances(ctx, gw.ID.String())
	if err != nil {
		return Source{}, fmt.Errorf("secret stores: list data-plane instances: %w", err)
	}
	return dataPlaneSource(gw.ID, instances, r.cfg.Now()), nil
}

func (r *sourceResolver) adminStores(gwID ids.GatewayID) []StoreView {
	var out []StoreView
	for _, st := range r.cfg.Health.Statuses() {
		if !admits(st.Gateways, gwID) {
			continue
		}
		out = append(out, StoreView{
			Name: st.Name, Type: st.Type, AllowedPaths: st.AllowedPaths, AllowedDestinations: st.AllowedDestinations, Consistent: true,
			Status:    aggregate([]string{string(st.State)}),
			Instances: []InstanceView{viewOf(r.cfg.AdminInstance, "", st)},
		})
	}
	return out
}

func dataPlaneSource(gwID ids.GatewayID, instances []dataplane.Instance, now time.Time) Source {
	src := Source{Supported: true, Kind: KindDataPlane}
	byName := map[string]*StoreView{}
	first := map[string]domain.Status{}
	states := map[string][]string{}
	for _, in := range instances {
		if !in.Live(now) {
			continue
		}
		src.Live++
		if !in.AcceptsSecretRefs {
			src.TooOld = append(src.TooOld, InstanceView{InstanceID: in.ID, Version: in.Version, State: InstanceStateTooOld})
			continue
		}
		src.refs = append(src.refs, in.SecretRefs)
		for _, st := range in.SecretStores {
			if !admits(st.Gateways, gwID) {
				continue
			}
			view, ok := byName[st.Name]
			if !ok {
				view = &StoreView{Name: st.Name, Type: st.Type, AllowedPaths: st.AllowedPaths, AllowedDestinations: st.AllowedDestinations, Consistent: true}
				byName[st.Name] = view
				first[st.Name] = st
			} else if !sameStore(first[st.Name], st) {
				view.Consistent = false
			}
			view.Instances = append(view.Instances, viewOf(in.ID, in.Version, st))
			view.instancePaths = append(view.instancePaths, st.AllowedPaths)
			view.instanceDestinations = append(view.instanceDestinations, st.AllowedDestinations)
			states[st.Name] = append(states[st.Name], string(st.State))
		}
	}
	for name, view := range byName {
		view.Status = aggregate(states[name])
		src.Stores = append(src.Stores, *view)
	}
	sort.Slice(src.Stores, func(i, j int) bool { return src.Stores[i].Name < src.Stores[j].Name })
	return src
}

func viewOf(instanceID, version string, st domain.Status) InstanceView {
	return InstanceView{
		InstanceID: instanceID, Version: version, State: string(st.State),
		ErrorClass: string(st.ErrorClass), CheckedAt: st.CheckedAt,
	}
}

func admits(allowlist []ids.GatewayID, gw ids.GatewayID) bool {
	return len(allowlist) == 0 || slices.Contains(allowlist, gw)
}

func sameStore(a, b domain.Status) bool {
	return a.Type == b.Type && slices.Equal(a.AllowedPaths, b.AllowedPaths) && slices.Equal(a.Gateways, b.Gateways) &&
		slices.Equal(a.AllowedDestinations, b.AllowedDestinations)
}

// aggregate is ok when every instance is ok, down when none is, and
// degraded otherwise.
func aggregate(states []string) string {
	ok := 0
	for _, s := range states {
		if s == string(domain.StateOK) {
			ok++
		}
	}
	switch {
	case len(states) == 0:
		return StatusNotReported
	case ok == len(states):
		return StatusOK
	case ok == 0:
		return StatusDown
	default:
		return StatusDegraded
	}
}

// AllowsPath reports whether some instance that reports the store allows
// path, whatever order the instances were listed in; "*" written explicitly
// allows every path.
func (s StoreView) AllowsPath(path string) bool {
	if len(s.instancePaths) == 0 {
		st := domain.Store{AllowedPaths: s.AllowedPaths}
		return st.AllowsPath(path)
	}
	for _, paths := range s.instancePaths {
		st := domain.Store{AllowedPaths: paths}
		if st.AllowsPath(path) {
			return true
		}
	}
	return false
}

// AllowsDestinations reports whether every instance that reports the store
// would send a value to hosts: each one enforces its own list, so a value
// one of them refuses would fail there.
func (s StoreView) AllowsDestinations(hosts []string) error {
	lists := s.instanceDestinations
	if len(lists) == 0 {
		lists = [][]string{s.AllowedDestinations}
	}
	for _, destinations := range lists {
		st := domain.Store{Name: s.Name, AllowedDestinations: destinations}
		if err := st.AllowsDestinations(hosts); err != nil {
			return err
		}
	}
	return nil
}
