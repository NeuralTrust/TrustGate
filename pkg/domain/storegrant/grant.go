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

// Package storegrant is the MCP Store's access model: who may use which
// catalog server on a gateway. A grant is keyed by catalog code — the whole
// catalog is grantable, whether or not a registry exists for the code yet — and
// optionally narrowed to one configured instance (a registry) of that code, so
// an admin can hand the Finance group only the "Snowflake (finance)" instance
// while granting Engineering every Snowflake instance.
//
// Grants are gateway configuration, not per-principal state: they ride the
// config snapshot to the data planes like registries do, and are edited only
// from the Access page (or by approving a request).
package storegrant

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

var (
	ErrInvalidGrant = fmt.Errorf("store grant: invalid grant: %w", commonerrors.ErrValidation)
	ErrNotFound     = fmt.Errorf("store grant: not found: %w", commonerrors.ErrNotFound)
)

// Grant says which principals may use a catalog server on a gateway.
//
// A code-level grant (RegistryID nil) covers every configured instance of the
// code, and lets a granted principal install the server before any instance
// exists (the registry is materialised from the catalog on first install). An
// instance-level grant (RegistryID set) covers that one registry only.
//
// Groups are matched against the caller's token group claim, Users against the
// token subject. Grants are explicit: a grant with neither is granted to nobody
// and is treated as absent.
type Grant struct {
	GatewayID   ids.GatewayID
	CatalogCode string
	RegistryID  ids.RegistryID
	Groups      []string
	Users       []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// New builds a validated grant. registryID may be the zero id for a code-level
// grant. Subjects are trimmed, de-duplicated and sorted so two grants with the
// same members compare and serialise identically.
func New(gatewayID ids.GatewayID, code string, registryID ids.RegistryID, groups, users []string) (*Grant, error) {
	g := &Grant{
		GatewayID:   gatewayID,
		CatalogCode: strings.TrimSpace(code),
		RegistryID:  registryID,
		Groups:      normalizeSubjects(groups),
		Users:       normalizeSubjects(users),
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	g.CreatedAt, g.UpdatedAt = now, now
	return g, nil
}

// Validate checks the grant's identity; an empty member list is valid (it is how
// a grant is cleared).
func (g *Grant) Validate() error {
	if g == nil {
		return fmt.Errorf("%w: nil grant", ErrInvalidGrant)
	}
	if g.GatewayID.IsNil() {
		return fmt.Errorf("%w: gateway id is required", ErrInvalidGrant)
	}
	if strings.TrimSpace(g.CatalogCode) == "" {
		return fmt.Errorf("%w: catalog code is required", ErrInvalidGrant)
	}
	return nil
}

// grantJSON is the wire form: registry_id is present only on instance grants
// (omitempty does not apply to a fixed-size uuid array, so it is a pointer here).
type grantJSON struct {
	GatewayID   ids.GatewayID   `json:"gateway_id"`
	CatalogCode string          `json:"catalog_code"`
	RegistryID  *ids.RegistryID `json:"registry_id,omitempty"`
	Groups      []string        `json:"groups,omitempty"`
	Users       []string        `json:"users,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// MarshalJSON omits registry_id for a code-level grant.
func (g Grant) MarshalJSON() ([]byte, error) {
	out := grantJSON{
		GatewayID: g.GatewayID, CatalogCode: g.CatalogCode,
		Groups: g.Groups, Users: g.Users, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt,
	}
	if !g.RegistryID.IsNil() {
		id := g.RegistryID
		out.RegistryID = &id
	}
	return json.Marshal(out)
}

// UnmarshalJSON accepts an absent, null or nil-uuid registry_id as code-level.
func (g *Grant) UnmarshalJSON(data []byte) error {
	var in grantJSON
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	*g = Grant{
		GatewayID: in.GatewayID, CatalogCode: in.CatalogCode,
		Groups: in.Groups, Users: in.Users, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt,
	}
	if in.RegistryID != nil {
		g.RegistryID = *in.RegistryID
	}
	return nil
}

// IsInstance reports whether the grant is narrowed to one configured instance.
func (g *Grant) IsInstance() bool { return g != nil && !g.RegistryID.IsNil() }

// IsEmpty reports whether the grant names nobody — equivalent to no grant.
func (g *Grant) IsEmpty() bool { return g == nil || (len(g.Groups) == 0 && len(g.Users) == 0) }

// Allows reports whether a principal with these groups and subject is named by
// the grant: their subject is in Users, or one of their groups is in Groups.
func (g *Grant) Allows(groups []string, subject string) bool {
	if g == nil {
		return false
	}
	if sub := strings.TrimSpace(subject); sub != "" {
		for _, u := range g.Users {
			if u == sub {
				return true
			}
		}
	}
	if len(g.Groups) == 0 || len(groups) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(groups))
	for _, grp := range groups {
		if grp = strings.TrimSpace(grp); grp != "" {
			set[grp] = struct{}{}
		}
	}
	for _, a := range g.Groups {
		if _, ok := set[a]; ok {
			return true
		}
	}
	return false
}

// AddUser names one more subject on the grant; a no-op when already named.
// Returns whether the grant changed.
func (g *Grant) AddUser(subject string) bool {
	sub := strings.TrimSpace(subject)
	if g == nil || sub == "" {
		return false
	}
	for _, u := range g.Users {
		if u == sub {
			return false
		}
	}
	g.Users = normalizeSubjects(append(g.Users, sub))
	g.UpdatedAt = time.Now().UTC()
	return true
}

func normalizeSubjects(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// Reader is the read side every plane has: the grants of one gateway. On the
// control plane it is the Postgres repository; on the data plane it reads the
// config snapshot.
type Reader interface {
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Grant, error)
}

// Repository is the control-plane store. Upsert is keyed by
// (gateway, code, registry): saving a grant with no members deletes it.
//
//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=store_grant_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Reader
	// List pages every grant across gateways (the snapshot compiler's bulk read).
	List(ctx context.Context, page, size int) ([]*Grant, int, error)
	// Upsert creates or replaces the grant for (gateway, code, registry). A grant
	// naming nobody is deleted instead, so the table never holds empty rows.
	Upsert(ctx context.Context, g *Grant) error
	// Delete removes the grant for (gateway, code, registry); missing is not an
	// error.
	Delete(ctx context.Context, gatewayID ids.GatewayID, code string, registryID ids.RegistryID) error
	// DeleteByRegistry removes every instance-level grant on one registry — called
	// when the registry is deleted so no dangling grant survives.
	DeleteByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error
}

// Set is the in-memory index of one gateway's grants that install, scope and
// search decisions run against.
type Set struct {
	byCode     map[string]*Grant
	byRegistry map[ids.RegistryID]*Grant
	// instancesByCode lists the instance-level grants of a code, for "is any
	// instance of this code granted to me" checks.
	instancesByCode map[string][]*Grant
}

// Index builds a Set. Empty grants are skipped (granted to nobody = absent).
func Index(grants []*Grant) *Set {
	s := &Set{
		byCode:          make(map[string]*Grant),
		byRegistry:      make(map[ids.RegistryID]*Grant),
		instancesByCode: make(map[string][]*Grant),
	}
	for _, g := range grants {
		if g == nil || g.IsEmpty() {
			continue
		}
		if g.IsInstance() {
			s.byRegistry[g.RegistryID] = g
			s.instancesByCode[g.CatalogCode] = append(s.instancesByCode[g.CatalogCode], g)
			continue
		}
		s.byCode[g.CatalogCode] = g
	}
	return s
}

// Code returns the code-level grant, or nil.
func (s *Set) Code(code string) *Grant {
	if s == nil {
		return nil
	}
	return s.byCode[code]
}

// Instance returns the instance-level grant on a registry, or nil.
func (s *Set) Instance(registryID ids.RegistryID) *Grant {
	if s == nil || registryID.IsNil() {
		return nil
	}
	return s.byRegistry[registryID]
}

// CodeAllows reports whether the principal holds the code-level grant: every
// instance of the code, and the right to materialise it.
func (s *Set) CodeAllows(code string, groups []string, subject string) bool {
	return s.Code(code).Allows(groups, subject)
}

// InstanceAllows reports whether the principal may use one specific instance:
// through the code-level grant or a grant on that instance.
func (s *Set) InstanceAllows(code string, registryID ids.RegistryID, groups []string, subject string) bool {
	if s.CodeAllows(code, groups, subject) {
		return true
	}
	return s.Instance(registryID).Allows(groups, subject)
}

// AnyInstanceAllows reports whether the principal holds at least one
// instance-level grant on the code (regardless of the code-level grant).
func (s *Set) AnyInstanceAllows(code string, groups []string, subject string) bool {
	if s == nil {
		return false
	}
	for _, g := range s.instancesByCode[code] {
		if g.Allows(groups, subject) {
			return true
		}
	}
	return false
}
