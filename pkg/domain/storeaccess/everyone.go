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

package storeaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ErrInvalidEveryone wraps every validation failure of an Everyone object.
var ErrInvalidEveryone = fmt.Errorf("store everyone: invalid everyone: %w", commonerrors.ErrValidation)

// Everyone is a gateway's shared Store access: a level and a set of servers
// that every group passes on to its members, except the excluded groups and
// groups whose own policy is "none". It only ever adds to what a caller has.
type Everyone struct {
	GatewayID      ids.GatewayID
	Mode           string
	Grants         []EveryoneGrant
	ExcludedGroups []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EveryoneGrant names one server of Everyone: every instance of a catalog code
// when RegistryID is nil, else that one registry.
type EveryoneGrant struct {
	CatalogCode string
	RegistryID  ids.RegistryID
}

// IsInstance reports whether the grant is narrowed to one configured instance.
func (g EveryoneGrant) IsInstance() bool { return !g.RegistryID.IsNil() }

// NewEveryone builds a validated Everyone object. Grants are de-duplicated and
// sorted, and excluded groups trimmed, de-duplicated and sorted, so two equal
// objects serialise identically.
func NewEveryone(gatewayID ids.GatewayID, mode string, grants []EveryoneGrant, excludedGroups []string) (*Everyone, error) {
	e := &Everyone{
		GatewayID:      gatewayID,
		Mode:           strings.ToLower(strings.TrimSpace(mode)),
		Grants:         normalizeEveryoneGrants(grants),
		ExcludedGroups: normalizeSubjects(excludedGroups),
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	e.CreatedAt, e.UpdatedAt = now, now
	return e, nil
}

// Validate checks the gateway, the mode and the grants. "none" is refused, and
// so is "curated" without grants: an absent object is the only way to say
// Everyone gives nothing.
func (e *Everyone) Validate() error {
	if e == nil {
		return fmt.Errorf("%w: nil everyone", ErrInvalidEveryone)
	}
	if e.GatewayID.IsNil() {
		return fmt.Errorf("%w: gateway id is required", ErrInvalidEveryone)
	}
	switch e.Mode {
	case gatewaydomain.StoreModeOpen:
	case gatewaydomain.StoreModeCurated:
		if len(e.Grants) == 0 {
			return fmt.Errorf("%w: curated needs at least one grant", ErrInvalidEveryone)
		}
	default:
		return fmt.Errorf("%w: mode must be open or curated", ErrInvalidEveryone)
	}
	for _, g := range e.Grants {
		if strings.TrimSpace(g.CatalogCode) == "" {
			return fmt.Errorf("%w: catalog code is required", ErrInvalidEveryone)
		}
	}
	return nil
}

// Excludes reports whether a group key is in the excluded list.
func (e *Everyone) Excludes(group string) bool {
	if e == nil {
		return false
	}
	group = strings.TrimSpace(group)
	for _, g := range e.ExcludedGroups {
		if g == group {
			return true
		}
	}
	return false
}

// WithoutRegistry returns a copy without the instance grants on registryID, and
// whether anything was removed.
func (e *Everyone) WithoutRegistry(registryID ids.RegistryID) (*Everyone, bool) {
	if e == nil || registryID.IsNil() {
		return e, false
	}
	kept := make([]EveryoneGrant, 0, len(e.Grants))
	for _, g := range e.Grants {
		if g.RegistryID == registryID {
			continue
		}
		kept = append(kept, g)
	}
	if len(kept) == len(e.Grants) {
		return e, false
	}
	out := *e
	out.Grants = kept
	out.UpdatedAt = time.Now().UTC()
	return &out, true
}

func normalizeEveryoneGrants(in []EveryoneGrant) []EveryoneGrant {
	if len(in) == 0 {
		return nil
	}
	type key struct {
		code     string
		registry ids.RegistryID
	}
	seen := make(map[key]struct{}, len(in))
	out := make([]EveryoneGrant, 0, len(in))
	for _, g := range in {
		g.CatalogCode = strings.TrimSpace(g.CatalogCode)
		k := key{g.CatalogCode, g.RegistryID}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CatalogCode != out[j].CatalogCode {
			return out[i].CatalogCode < out[j].CatalogCode
		}
		return out[i].RegistryID.String() < out[j].RegistryID.String()
	})
	return out
}

type everyoneGrantJSON struct {
	CatalogCode string          `json:"catalog_code"`
	RegistryID  *ids.RegistryID `json:"registry_id,omitempty"`
}

// MarshalJSON omits registry_id for a code-level grant.
func (g EveryoneGrant) MarshalJSON() ([]byte, error) {
	out := everyoneGrantJSON{CatalogCode: g.CatalogCode}
	if !g.RegistryID.IsNil() {
		id := g.RegistryID
		out.RegistryID = &id
	}
	return json.Marshal(out)
}

// UnmarshalJSON accepts an absent, null or nil-uuid registry_id as code-level.
func (g *EveryoneGrant) UnmarshalJSON(data []byte) error {
	var in everyoneGrantJSON
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	*g = EveryoneGrant{CatalogCode: in.CatalogCode}
	if in.RegistryID != nil {
		g.RegistryID = *in.RegistryID
	}
	return nil
}

type everyoneJSON struct {
	GatewayID      ids.GatewayID   `json:"gateway_id"`
	Mode           string          `json:"mode"`
	Grants         []EveryoneGrant `json:"grants,omitempty"`
	ExcludedGroups []string        `json:"excluded_groups,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// MarshalJSON is the snapshot wire form.
func (e Everyone) MarshalJSON() ([]byte, error) {
	return json.Marshal(everyoneJSON(e))
}

// UnmarshalJSON reads the snapshot wire form.
func (e *Everyone) UnmarshalJSON(data []byte) error {
	var in everyoneJSON
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	*e = Everyone(in)
	return nil
}

// EveryoneReader is the read side every plane has: one gateway's Everyone
// object, or nil when the gateway has none.
type EveryoneReader interface {
	GetEveryone(ctx context.Context, gatewayID ids.GatewayID) (*Everyone, error)
}

// EveryoneRepository is the control-plane store, one row per gateway.
//
//go:generate mockery --name=EveryoneRepository --dir=. --output=./mocks --filename=store_everyone_repository_mock.go --case=underscore --with-expecter
type EveryoneRepository interface {
	EveryoneReader
	// ListEveryone pages every gateway's object (snapshot compiler).
	ListEveryone(ctx context.Context, page, size int) ([]*Everyone, int, error)
	// UpsertEveryone creates or replaces the gateway's object.
	UpsertEveryone(ctx context.Context, e *Everyone) error
	// DeleteEveryone removes the gateway's object; missing is not an error.
	DeleteEveryone(ctx context.Context, gatewayID ids.GatewayID) error
}
