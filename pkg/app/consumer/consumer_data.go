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
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
)

type RoutableConsumer struct {
	Consumer   *domain.Consumer
	Registries []*registrydomain.Registry

	FallbackBackends []*registrydomain.Registry
	Policies         []*policydomain.Policy
	Auths            []*authdomain.Auth
	PolicyPlan       *appplugins.StagePlan
}

type Data struct {
	GatewayID    ids.GatewayID
	Consumers    []RoutableConsumer
	Roles        []*roledomain.Role
	bySlug       map[string]*RoutableConsumer
	registryByID map[ids.RegistryID]*registrydomain.Registry
}

func NewData(gatewayID ids.GatewayID, consumers []RoutableConsumer, roles ...[]*roledomain.Role) *Data {
	d := &Data{GatewayID: gatewayID, Consumers: consumers}
	if len(roles) > 0 {
		d.Roles = roles[0]
	}
	d.indexBySlug()
	d.indexRegistries()
	return d
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

func (d *Data) EffectiveRegistries(rc *RoutableConsumer) []*registrydomain.Registry {
	if rc == nil || rc.Consumer == nil {
		return nil
	}
	if rc.Consumer.RoutingMode != domain.RoutingModeRoleBased {
		return rc.Registries
	}
	assigned := make(map[ids.RoleID]struct{}, len(rc.Consumer.RoleIDs))
	for _, id := range rc.Consumer.RoleIDs {
		assigned[id] = struct{}{}
	}
	seen := make(map[ids.RegistryID]struct{})
	out := make([]*registrydomain.Registry, 0)
	for _, role := range d.Roles {
		if role == nil {
			continue
		}
		if _, ok := assigned[role.ID]; !ok {
			continue
		}
		for _, id := range role.RegistryIDs {
			reg, ok := d.RegistryByID(id)
			if !ok || !reg.IsMCP() {
				continue
			}
			if _, dup := seen[reg.ID]; dup {
				continue
			}
			seen[reg.ID] = struct{}{}
			out = append(out, reg)
		}
	}
	return out
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
		if rc.Consumer == nil || !rc.Consumer.Active || rc.Consumer.Slug == "" {
			continue
		}
		d.bySlug[rc.Consumer.Slug] = rc
	}
}
