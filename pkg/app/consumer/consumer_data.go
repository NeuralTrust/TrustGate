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

package consumer

import (
	"bytes"
	"cmp"
	"slices"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type RoutableConsumer struct {
	Consumer   *domain.Consumer
	Registries []*registrydomain.Registry

	FallbackBackends []*registrydomain.Registry
	Auths            []*authdomain.Auth

	// Policies and PolicyPlan hold the same set of policies, always. The
	// executor accepts both and rebuilds the chain from Policies whenever
	// PolicyPlan is nil, so a set that appears in one and not the other would
	// be executed under an ordering the plan never agreed to. For a non-MCP
	// consumer PolicyPlan is therefore never nil: its set includes the
	// group-only policies whose specificity only the inert plan flattens
	// (RUN-1621, rule 4).
	Policies   []*policydomain.Policy
	PolicyPlan *appplugins.StagePlan

	// ScopedPolicies are the policies carrying an MCPScope, kept apart so the
	// MCP tools/call path can select among them per destination. A non-MCP
	// consumer also carries them, and they are inert there: only the subset
	// that crosses planes is folded into Policies and PolicyPlan.
	ScopedPolicies []*policydomain.Policy

	// MCPPlans are the precompiled per-destination plans the MCP tools/call
	// path selects from; nil for consumers that are not MCP.
	MCPPlans *PolicyPlans
}

// StoreLink is one personal consumer an owned key is linked to, with the
// attributes of that link.
type StoreLink struct {
	Consumer *RoutableConsumer
	Link     domain.AuthLink
}

type Data struct {
	GatewayID     ids.GatewayID
	Consumers     []RoutableConsumer
	StoreConsumer *RoutableConsumer
	bySlug        map[string]*RoutableConsumer
	registryByID  map[ids.RegistryID]*registrydomain.Registry
	storeLinks    map[ids.AuthID][]StoreLink
	personal      int
}

func NewData(gatewayID ids.GatewayID, consumers []RoutableConsumer) *Data {
	d := &Data{GatewayID: gatewayID, Consumers: consumers}
	d.indexBySlug()
	d.indexRegistries()
	d.indexStoreLinks()
	return d
}

// HasPersonalConsumers reports whether the gateway has at least one active
// personal consumer.
func (d *Data) HasPersonalConsumers() bool {
	return d != nil && d.personal > 0
}

// StoreLinks returns the personal consumers the auth is linked to, in
// selection order. The slice is shared by every reader and must not be
// modified.
func (d *Data) StoreLinks(id ids.AuthID) []StoreLink {
	if d == nil {
		return nil
	}
	return d.storeLinks[id]
}

func (d *Data) indexStoreLinks() {
	d.storeLinks = make(map[ids.AuthID][]StoreLink)
	for i := range d.Consumers {
		rc := &d.Consumers[i]
		if rc.Consumer == nil || !rc.Consumer.Active || !rc.Consumer.IsPersonal() {
			continue
		}
		d.personal++
		for _, authID := range rc.Consumer.AuthIDs {
			if link, ok := rc.Consumer.AuthLinks[authID]; ok {
				d.storeLinks[authID] = append(d.storeLinks[authID], StoreLink{Consumer: rc, Link: link})
			}
		}
	}
	for id, links := range d.storeLinks {
		slices.SortFunc(links, compareStoreLinks)
		d.storeLinks[id] = slices.Clip(links)
	}
}

func compareStoreLinks(a, b StoreLink) int {
	idA, idB := a.Consumer.Consumer.ID.UUID(), b.Consumer.Consumer.ID.UUID()
	return cmp.Or(
		cmp.Compare(a.Link.Level.Rank(), b.Link.Level.Rank()),
		cmp.Compare(a.Link.Priority, b.Link.Priority),
		a.Link.GrantedAt.Compare(b.Link.GrantedAt),
		bytes.Compare(idA[:], idB[:]),
	)
}

func (d *Data) SetRegistryIndex(byID map[ids.RegistryID]*registrydomain.Registry) {
	for id, reg := range byID {
		d.registryByID[id] = reg
	}
}

func (d *Data) RegistryByID(id ids.RegistryID) (*registrydomain.Registry, bool) {
	if d == nil || d.registryByID == nil {
		return nil, false
	}
	reg, ok := d.registryByID[id]
	return reg, ok
}

func (d *Data) indexRegistries() {
	d.registryByID = make(map[ids.RegistryID]*registrydomain.Registry)
	for i := range d.Consumers {
		for _, reg := range d.Consumers[i].Registries {
			d.registryByID[reg.ID] = reg
		}
		for _, reg := range d.Consumers[i].FallbackBackends {
			d.registryByID[reg.ID] = reg
		}
	}
}

// EffectiveRegistries returns the registries a consumer routes to. Every
// consumer routes inline over its own registry associations.
func (d *Data) EffectiveRegistries(rc *RoutableConsumer) []*registrydomain.Registry {
	if rc == nil || rc.Consumer == nil {
		return nil
	}
	return rc.Registries
}

func (d *Data) MatchSlug(slug string) (*RoutableConsumer, bool) {
	if d == nil || d.bySlug == nil {
		return nil, false
	}
	rc, ok := d.bySlug[slug]
	return rc, ok
}

func (d *Data) MatchPath(path string) (*RoutableConsumer, bool) {
	slug := SlugFromMCPPath(path)
	if slug == "" {
		return nil, false
	}
	return d.MatchSlug(slug)
}

func MCPPath(slug string) string {
	return "/" + slug + "/mcp"
}

func (d *Data) indexBySlug() {
	d.bySlug = make(map[string]*RoutableConsumer, len(d.Consumers))
	for i := range d.Consumers {
		rc := &d.Consumers[i]
		if rc.Consumer == nil || !rc.Consumer.Active || rc.Consumer.Slug == "" || rc.Consumer.IsPersonal() {
			continue
		}
		d.bySlug[rc.Consumer.Slug] = rc
	}
}
