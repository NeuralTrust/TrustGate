package readmodel

import (
	"sort"
	"strings"
	"time"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
)

type CatalogModel struct {
	ProviderCode string
	Model        catalogdomain.Model
}

type Data struct {
	Version       string
	Gateways      []gatewaydomain.Gateway
	Consumers     []consumerdomain.Consumer
	Registries    []registrydomain.Registry
	Policies      []policydomain.Policy
	Auths         []authdomain.Auth
	Roles         []roledomain.Role
	Providers     []catalogdomain.Provider
	CatalogModels []CatalogModel
}

type Snapshot struct {
	data Data

	gatewaysByID     map[ids.GatewayID]*gatewaydomain.Gateway
	gatewaysBySlug   map[string]*gatewaydomain.Gateway
	gatewaysByDomain map[string]*gatewaydomain.Gateway

	consumersByID       map[ids.ConsumerID]*consumerdomain.Consumer
	consumersByGateway  map[ids.GatewayID][]*consumerdomain.Consumer
	consumersActiveSlug map[string]*consumerdomain.Consumer
	consumersByAuth     map[ids.AuthID][]*consumerdomain.Consumer

	registriesByID      map[ids.RegistryID]*registrydomain.Registry
	registriesByGateway map[ids.GatewayID]map[ids.RegistryID]*registrydomain.Registry

	policiesByID      map[ids.PolicyID]*policydomain.Policy
	policiesByGateway map[ids.GatewayID]map[ids.PolicyID]*policydomain.Policy
	policiesOrdered   map[ids.GatewayID][]*policydomain.Policy

	authsByID           map[ids.AuthID]*authdomain.Auth
	authsByGateway      map[ids.GatewayID]map[ids.AuthID]*authdomain.Auth
	authsByAPIKeyHash   map[string]*authdomain.Auth
	authsEnabledByAge   []*authdomain.Auth
	authsEnabledGateway map[ids.GatewayID][]*authdomain.Auth

	rolesByID      map[ids.RoleID]*roledomain.Role
	rolesByGateway map[ids.GatewayID]map[ids.RoleID]*roledomain.Role
	rolesOrdered   map[ids.GatewayID][]*roledomain.Role

	providersOrdered      []*catalogdomain.Provider
	catalogByProviderSlug map[string]*catalogdomain.Model
	catalogByProviderCode map[string][]*catalogdomain.Model
	catalogAll            []*catalogdomain.Model
}

func Build(data Data) *Snapshot {
	s := &Snapshot{
		data:                  data,
		gatewaysByID:          make(map[ids.GatewayID]*gatewaydomain.Gateway, len(data.Gateways)),
		gatewaysBySlug:        make(map[string]*gatewaydomain.Gateway, len(data.Gateways)),
		gatewaysByDomain:      make(map[string]*gatewaydomain.Gateway),
		consumersByID:         make(map[ids.ConsumerID]*consumerdomain.Consumer, len(data.Consumers)),
		consumersByGateway:    make(map[ids.GatewayID][]*consumerdomain.Consumer),
		consumersActiveSlug:   make(map[string]*consumerdomain.Consumer),
		consumersByAuth:       make(map[ids.AuthID][]*consumerdomain.Consumer),
		registriesByID:        make(map[ids.RegistryID]*registrydomain.Registry, len(data.Registries)),
		registriesByGateway:   make(map[ids.GatewayID]map[ids.RegistryID]*registrydomain.Registry),
		policiesByID:          make(map[ids.PolicyID]*policydomain.Policy, len(data.Policies)),
		policiesByGateway:     make(map[ids.GatewayID]map[ids.PolicyID]*policydomain.Policy),
		policiesOrdered:       make(map[ids.GatewayID][]*policydomain.Policy),
		authsByID:             make(map[ids.AuthID]*authdomain.Auth, len(data.Auths)),
		authsByGateway:        make(map[ids.GatewayID]map[ids.AuthID]*authdomain.Auth),
		authsByAPIKeyHash:     make(map[string]*authdomain.Auth),
		authsEnabledGateway:   make(map[ids.GatewayID][]*authdomain.Auth),
		rolesByID:             make(map[ids.RoleID]*roledomain.Role, len(data.Roles)),
		rolesByGateway:        make(map[ids.GatewayID]map[ids.RoleID]*roledomain.Role),
		rolesOrdered:          make(map[ids.GatewayID][]*roledomain.Role),
		catalogByProviderSlug: make(map[string]*catalogdomain.Model, len(data.CatalogModels)),
		catalogByProviderCode: make(map[string][]*catalogdomain.Model),
		catalogAll:            make([]*catalogdomain.Model, 0, len(data.CatalogModels)),
	}

	s.buildGateways()
	s.buildConsumers()
	s.buildRegistries()
	s.buildPolicies()
	s.buildAuths()
	s.buildRoles()
	s.buildCatalog()

	return s
}

func (s *Snapshot) buildGateways() {
	for i := range s.data.Gateways {
		g := &s.data.Gateways[i]
		s.gatewaysByID[g.ID] = g
		if slug := gatewaydomain.NormalizeSlug(g.Slug); slug != "" {
			s.gatewaysBySlug[slug] = g
		}
		if g.Domain != "" {
			s.gatewaysByDomain[g.Domain] = g
		}
	}
}

func (s *Snapshot) buildConsumers() {
	ordered := make([]*consumerdomain.Consumer, len(s.data.Consumers))
	for i := range s.data.Consumers {
		ordered[i] = &s.data.Consumers[i]
	}
	sort.SliceStable(ordered, func(a, b int) bool {
		return recencyDescIDAsc(ordered[a].CreatedAt, ordered[a].ID.String(), ordered[b].CreatedAt, ordered[b].ID.String())
	})
	for _, c := range ordered {
		s.consumersByID[c.ID] = c
		s.consumersByGateway[c.GatewayID] = append(s.consumersByGateway[c.GatewayID], c)
		if c.Active {
			s.consumersActiveSlug[strings.TrimSpace(c.Slug)] = c
		}
		for _, authID := range c.AuthIDs {
			s.consumersByAuth[authID] = append(s.consumersByAuth[authID], c)
		}
	}
}

func (s *Snapshot) buildRegistries() {
	for i := range s.data.Registries {
		r := &s.data.Registries[i]
		s.registriesByID[r.ID] = r
		byID, ok := s.registriesByGateway[r.GatewayID]
		if !ok {
			byID = make(map[ids.RegistryID]*registrydomain.Registry)
			s.registriesByGateway[r.GatewayID] = byID
		}
		byID[r.ID] = r
	}
}

func (s *Snapshot) buildPolicies() {
	ordered := make([]*policydomain.Policy, len(s.data.Policies))
	for i := range s.data.Policies {
		ordered[i] = &s.data.Policies[i]
	}
	sort.SliceStable(ordered, func(a, b int) bool {
		x, y := ordered[a], ordered[b]
		if x.Priority != y.Priority {
			return x.Priority < y.Priority
		}
		if !x.CreatedAt.Equal(y.CreatedAt) {
			return x.CreatedAt.Before(y.CreatedAt)
		}
		return x.ID.String() < y.ID.String()
	})
	for _, p := range ordered {
		s.policiesByID[p.ID] = p
		byID, ok := s.policiesByGateway[p.GatewayID]
		if !ok {
			byID = make(map[ids.PolicyID]*policydomain.Policy)
			s.policiesByGateway[p.GatewayID] = byID
		}
		byID[p.ID] = p
		s.policiesOrdered[p.GatewayID] = append(s.policiesOrdered[p.GatewayID], p)
	}
}

func (s *Snapshot) buildAuths() {
	for i := range s.data.Auths {
		a := &s.data.Auths[i]
		s.authsByID[a.ID] = a
		byID, ok := s.authsByGateway[a.GatewayID]
		if !ok {
			byID = make(map[ids.AuthID]*authdomain.Auth)
			s.authsByGateway[a.GatewayID] = byID
		}
		byID[a.ID] = a
		if a.Type == authdomain.TypeAPIKey && a.Enabled && a.KeyHash != "" {
			s.authsByAPIKeyHash[a.KeyHash] = a
		}
	}

	enabled := make([]*authdomain.Auth, 0, len(s.data.Auths))
	for i := range s.data.Auths {
		if s.data.Auths[i].Enabled {
			enabled = append(enabled, &s.data.Auths[i])
		}
	}

	byAge := append([]*authdomain.Auth(nil), enabled...)
	sort.SliceStable(byAge, func(a, b int) bool {
		return recencyAscIDAsc(byAge[a].CreatedAt, byAge[a].ID.String(), byAge[b].CreatedAt, byAge[b].ID.String())
	})
	s.authsEnabledByAge = byAge

	byGateway := append([]*authdomain.Auth(nil), enabled...)
	sort.SliceStable(byGateway, func(a, b int) bool {
		return recencyDescIDAsc(byGateway[a].CreatedAt, byGateway[a].ID.String(), byGateway[b].CreatedAt, byGateway[b].ID.String())
	})
	for _, a := range byGateway {
		s.authsEnabledGateway[a.GatewayID] = append(s.authsEnabledGateway[a.GatewayID], a)
	}
}

func (s *Snapshot) buildRoles() {
	ordered := make([]*roledomain.Role, len(s.data.Roles))
	for i := range s.data.Roles {
		ordered[i] = &s.data.Roles[i]
	}
	sort.SliceStable(ordered, func(a, b int) bool {
		return recencyDescIDAsc(ordered[a].CreatedAt, ordered[a].ID.String(), ordered[b].CreatedAt, ordered[b].ID.String())
	})
	for _, r := range ordered {
		s.rolesByID[r.ID] = r
		byID, ok := s.rolesByGateway[r.GatewayID]
		if !ok {
			byID = make(map[ids.RoleID]*roledomain.Role)
			s.rolesByGateway[r.GatewayID] = byID
		}
		byID[r.ID] = r
		s.rolesOrdered[r.GatewayID] = append(s.rolesOrdered[r.GatewayID], r)
	}
}

func (s *Snapshot) buildCatalog() {
	providers := make([]*catalogdomain.Provider, len(s.data.Providers))
	for i := range s.data.Providers {
		providers[i] = &s.data.Providers[i]
	}
	sort.SliceStable(providers, func(a, b int) bool { return providers[a].Code < providers[b].Code })
	s.providersOrdered = providers

	entries := make([]*CatalogModel, len(s.data.CatalogModels))
	for i := range s.data.CatalogModels {
		entries[i] = &s.data.CatalogModels[i]
	}
	sort.SliceStable(entries, func(a, b int) bool {
		if entries[a].ProviderCode != entries[b].ProviderCode {
			return entries[a].ProviderCode < entries[b].ProviderCode
		}
		return entries[a].Model.Slug < entries[b].Model.Slug
	})
	for _, e := range entries {
		model := &e.Model
		s.catalogByProviderSlug[catalogKey(e.ProviderCode, model.Slug)] = model
		s.catalogByProviderCode[e.ProviderCode] = append(s.catalogByProviderCode[e.ProviderCode], model)
		s.catalogAll = append(s.catalogAll, model)
	}
}

func catalogKey(providerCode, slug string) string {
	return providerCode + "\x00" + slug
}

func recencyDescIDAsc(at time.Time, id string, bt time.Time, bid string) bool {
	if !at.Equal(bt) {
		return at.After(bt)
	}
	return id < bid
}

func recencyAscIDAsc(at time.Time, id string, bt time.Time, bid string) bool {
	if !at.Equal(bt) {
		return at.Before(bt)
	}
	return id < bid
}

func (s *Snapshot) Version() string { return s.data.Version }

func (s *Snapshot) Data() Data { return s.data }

func (s *Snapshot) GatewayByID(id ids.GatewayID) (*gatewaydomain.Gateway, bool) {
	g, ok := s.gatewaysByID[id]
	return g, ok
}

func (s *Snapshot) GatewayBySlug(slug string) (*gatewaydomain.Gateway, bool) {
	g, ok := s.gatewaysBySlug[gatewaydomain.NormalizeSlug(slug)]
	return g, ok
}

func (s *Snapshot) GatewayByDomain(host string) (*gatewaydomain.Gateway, bool) {
	if host == "" {
		return nil, false
	}
	g, ok := s.gatewaysByDomain[host]
	return g, ok
}

func (s *Snapshot) ConsumerByID(id ids.ConsumerID) (*consumerdomain.Consumer, bool) {
	c, ok := s.consumersByID[id]
	return c, ok
}

func (s *Snapshot) ConsumersByGateway(gatewayID ids.GatewayID) []*consumerdomain.Consumer {
	return s.consumersByGateway[gatewayID]
}

func (s *Snapshot) ConsumerActiveBySlug(slug string) (*consumerdomain.Consumer, bool) {
	c, ok := s.consumersActiveSlug[strings.TrimSpace(slug)]
	return c, ok
}

func (s *Snapshot) ConsumersByAuthID(authID ids.AuthID) []*consumerdomain.Consumer {
	return s.consumersByAuth[authID]
}

func (s *Snapshot) RegistryByID(id ids.RegistryID) (*registrydomain.Registry, bool) {
	r, ok := s.registriesByID[id]
	return r, ok
}

func (s *Snapshot) RegistriesByIDs(gatewayID ids.GatewayID, registryIDs []ids.RegistryID) []*registrydomain.Registry {
	byID := s.registriesByGateway[gatewayID]
	if byID == nil {
		return nil
	}
	out := make([]*registrydomain.Registry, 0, len(registryIDs))
	seen := make(map[ids.RegistryID]struct{}, len(registryIDs))
	for _, id := range registryIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if r, ok := byID[id]; ok {
			out = append(out, r)
		}
	}
	return out
}

func (s *Snapshot) PolicyByID(id ids.PolicyID) (*policydomain.Policy, bool) {
	p, ok := s.policiesByID[id]
	return p, ok
}

func (s *Snapshot) PoliciesByIDs(gatewayID ids.GatewayID, policyIDs []ids.PolicyID) []*policydomain.Policy {
	byID := s.policiesByGateway[gatewayID]
	if byID == nil {
		return nil
	}
	out := make([]*policydomain.Policy, 0, len(policyIDs))
	seen := make(map[ids.PolicyID]struct{}, len(policyIDs))
	for _, id := range policyIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if p, ok := byID[id]; ok {
			out = append(out, p)
		}
	}
	return out
}

func (s *Snapshot) PoliciesByGateway(gatewayID ids.GatewayID) []*policydomain.Policy {
	return s.policiesOrdered[gatewayID]
}

func (s *Snapshot) AuthByID(id ids.AuthID) (*authdomain.Auth, bool) {
	a, ok := s.authsByID[id]
	return a, ok
}

func (s *Snapshot) AuthsByIDs(gatewayID ids.GatewayID, authIDs []ids.AuthID) []*authdomain.Auth {
	byID := s.authsByGateway[gatewayID]
	if byID == nil {
		return nil
	}
	out := make([]*authdomain.Auth, 0, len(authIDs))
	seen := make(map[ids.AuthID]struct{}, len(authIDs))
	for _, id := range authIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if a, ok := byID[id]; ok {
			out = append(out, a)
		}
	}
	return out
}

func (s *Snapshot) AuthByAPIKeyHash(keyHash string) (*authdomain.Auth, bool) {
	a, ok := s.authsByAPIKeyHash[keyHash]
	return a, ok
}

func (s *Snapshot) AuthsEnabledByTypes(types []authdomain.Type) []*authdomain.Auth {
	if len(types) == 0 {
		return nil
	}
	want := make(map[authdomain.Type]struct{}, len(types))
	for _, t := range types {
		want[t] = struct{}{}
	}
	out := make([]*authdomain.Auth, 0)
	for _, a := range s.authsEnabledByAge {
		if _, ok := want[a.Type]; ok {
			out = append(out, a)
		}
	}
	return out
}

func (s *Snapshot) AuthsEnabledByGatewayAndType(gatewayID ids.GatewayID, authType authdomain.Type) []*authdomain.Auth {
	out := make([]*authdomain.Auth, 0)
	for _, a := range s.authsEnabledGateway[gatewayID] {
		if a.Type == authType {
			out = append(out, a)
		}
	}
	return out
}

func (s *Snapshot) RoleByID(id ids.RoleID) (*roledomain.Role, bool) {
	r, ok := s.rolesByID[id]
	return r, ok
}

func (s *Snapshot) RolesByIDs(gatewayID ids.GatewayID, roleIDs []ids.RoleID) []*roledomain.Role {
	byID := s.rolesByGateway[gatewayID]
	if byID == nil {
		return nil
	}
	out := make([]*roledomain.Role, 0, len(roleIDs))
	seen := make(map[ids.RoleID]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if r, ok := byID[id]; ok {
			out = append(out, r)
		}
	}
	return out
}

func (s *Snapshot) RolesByGateway(gatewayID ids.GatewayID) []*roledomain.Role {
	return s.rolesOrdered[gatewayID]
}

func (s *Snapshot) Providers() []*catalogdomain.Provider {
	return s.providersOrdered
}

func (s *Snapshot) CatalogModelByProviderSlug(providerCode, slug string) (*catalogdomain.Model, bool) {
	m, ok := s.catalogByProviderSlug[catalogKey(providerCode, slug)]
	return m, ok
}

func (s *Snapshot) CatalogModelsByProviderCode(providerCode string) []*catalogdomain.Model {
	if providerCode == "" {
		return s.catalogAll
	}
	return s.catalogByProviderCode[providerCode]
}
