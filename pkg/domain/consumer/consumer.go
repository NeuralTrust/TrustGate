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
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
)

type Type string

const (
	TypeLLM Type = "LLM"
	TypeMCP Type = "MCP"
	TypeA2A Type = "A2A"
)

func Types() []Type {
	return []Type{TypeLLM, TypeMCP, TypeA2A}
}

func IsValidType(t Type) bool {
	switch t {
	case TypeLLM, TypeMCP, TypeA2A:
		return true
	}
	return false
}

const (
	// DefaultRegistryWeight is applied when a binding does not specify a weight.
	DefaultRegistryWeight = 1
	// MaxRegistryWeight caps per-association weights on a 1..100 relative scale
	// (read it like a percentage share within a pool). The weighted round-robin
	// scheduler iterates up to len(registries)*(maxWeight+1) times per pick, so a
	// bounded weight keeps a single request from monopolizing the lock.
	MaxRegistryWeight = 100
)

// RegistryBindings is a complete desired registry association set for a
// consumer, with the weight to apply to each member.
type RegistryBindings struct {
	IDs     []ids.RegistryID
	Weights map[ids.RegistryID]int
}

type Consumer struct {
	ID              ids.ConsumerID         `json:"id"`
	GatewayID       ids.GatewayID          `json:"gateway_id"`
	Name            string                 `json:"name"`
	Type            Type                   `json:"type"`
	Audience        Audience               `json:"audience,omitempty"`
	Slug            string                 `json:"slug"`
	LBConfig        *LBConfig              `json:"lb_config,omitempty"`
	Headers         map[string]string      `json:"headers,omitempty"`
	Active          bool                   `json:"active"`
	RegistryIDs     []ids.RegistryID       `json:"registry_ids"`
	RegistryWeights map[ids.RegistryID]int `json:"registry_weights,omitempty"`
	AuthIDs         []ids.AuthID           `json:"auth_ids"`
	Fallback        *Fallback              `json:"fallback,omitempty"`
	ModelPolicies   ModelPolicies          `json:"model_policies,omitempty"`
	MCP             *MCPPolicy             `json:"mcp,omitempty"`
	Identity        Identity               `json:"identity"`
	AuthBinding     AuthBinding            `json:"auth_binding"`
	// LabelSets are the traffic label sets the consumer's chat requests are
	// classified against. They are projected from the app and only ever
	// written through SetLabelSets.
	LabelSets []trafficlabel.LabelSet `json:"label_sets,omitempty"`
	AuthLinks map[ids.AuthID]AuthLink `json:"auth_links,omitempty"`
	CreatedAt time.Time               `json:"created_at"`
	UpdatedAt time.Time               `json:"updated_at"`
}

func (c *Consumer) WeightFor(registryID ids.RegistryID) int {
	if c.RegistryWeights == nil {
		return 1
	}
	if w, ok := c.RegistryWeights[registryID]; ok && w > 0 {
		return w
	}
	return 1
}

func (c *Consumer) Toolkit() Toolkit {
	if c.MCP == nil {
		return nil
	}
	return c.MCP.Toolkit
}

func (c *Consumer) FailMode() FailMode {
	if c.MCP == nil {
		return ""
	}
	return c.MCP.FailMode
}

// ActiveFallbackChain returns the fallback chain when fallback is enabled, and
// nil otherwise.
func (c *Consumer) ActiveFallbackChain() []ids.RegistryID {
	if c == nil || c.Fallback == nil || !c.Fallback.Enabled {
		return nil
	}
	return c.Fallback.Chain
}

type CreateParams struct {
	GatewayID       ids.GatewayID
	Name            string
	Type            Type
	Audience        Audience
	LBConfig        *LBConfig
	Headers         map[string]string
	Active          *bool
	RegistryIDs     []ids.RegistryID
	RegistryWeights map[ids.RegistryID]int
	AuthIDs         []ids.AuthID
	Fallback        *Fallback
	ModelPolicies   ModelPolicies
	MCP             *MCPPolicy
	Identity        *Identity
	AuthBinding     *AuthBinding
}

func New(params CreateParams) (*Consumer, error) {
	id, err := ids.NewV7[ids.ConsumerKind]()
	if err != nil {
		return nil, fmt.Errorf("consumer: generate uuid: %w", err)
	}
	slug, err := NewSlug()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	active := true
	if params.Active != nil {
		active = *params.Active
	}
	lbConfig := params.LBConfig
	if lbConfig != nil && lbConfig.Enabled && lbConfig.Algorithm == "" {
		copy := *lbConfig
		copy.Algorithm = algorithm.RoundRobin
		lbConfig = &copy
	}
	c := &Consumer{
		ID:              id,
		GatewayID:       params.GatewayID,
		Name:            params.Name,
		Type:            params.Type,
		Audience:        params.Audience,
		Slug:            slug,
		LBConfig:        lbConfig,
		Headers:         params.Headers,
		Active:          active,
		RegistryIDs:     params.RegistryIDs,
		RegistryWeights: params.RegistryWeights,
		AuthIDs:         params.AuthIDs,
		Fallback:        params.Fallback,
		ModelPolicies:   params.ModelPolicies,
		MCP:             params.MCP,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if params.Identity != nil {
		c.Identity = *params.Identity
	}
	if params.AuthBinding != nil {
		c.AuthBinding = *params.AuthBinding
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

type RehydrateParams struct {
	ID              ids.ConsumerID
	GatewayID       ids.GatewayID
	Name            string
	Type            Type
	Audience        Audience
	Slug            string
	LBConfig        *LBConfig
	Headers         map[string]string
	Active          bool
	RegistryIDs     []ids.RegistryID
	RegistryWeights map[ids.RegistryID]int
	AuthIDs         []ids.AuthID
	AuthLinks       map[ids.AuthID]AuthLink
	Fallback        *Fallback
	ModelPolicies   ModelPolicies
	MCP             *MCPPolicy
	Identity        Identity
	AuthBinding     AuthBinding
	LabelSets       []trafficlabel.LabelSet
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func Rehydrate(params RehydrateParams) *Consumer {
	return &Consumer{
		ID:              params.ID,
		GatewayID:       params.GatewayID,
		Name:            params.Name,
		Type:            params.Type,
		Audience:        params.Audience.canonical(),
		Slug:            params.Slug,
		LBConfig:        params.LBConfig,
		Headers:         params.Headers,
		Active:          params.Active,
		RegistryIDs:     params.RegistryIDs,
		RegistryWeights: params.RegistryWeights,
		AuthIDs:         params.AuthIDs,
		AuthLinks:       params.AuthLinks,
		Fallback:        params.Fallback,
		ModelPolicies:   params.ModelPolicies,
		MCP:             params.MCP,
		Identity:        params.Identity,
		AuthBinding:     params.AuthBinding,
		LabelSets:       params.LabelSets,
		CreatedAt:       params.CreatedAt,
		UpdatedAt:       params.UpdatedAt,
	}
}

func (c *Consumer) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidName)
	}
	if c.GatewayID.IsNil() {
		return ErrInvalidGatewayID
	}
	if c.Type == "" {
		c.Type = TypeLLM
	}
	if !IsValidType(c.Type) {
		return fmt.Errorf("%w: %q", ErrInvalidType, c.Type)
	}
	audience, err := ParseAudience(string(c.Audience))
	if err != nil {
		return err
	}
	c.Audience = audience
	if !IsValidSlug(c.Slug) {
		return fmt.Errorf("%w: %q", ErrInvalidSlug, c.Slug)
	}
	if err := validateUniqueIDs(c.AuthIDs, ErrInvalidAuthID, "auth"); err != nil {
		return err
	}
	if c.Type != TypeMCP && c.MCP != nil {
		return fmt.Errorf("%w: mcp policy is only valid for MCP consumers", ErrInvalidType)
	}
	c.Identity.Normalize(c.Type)
	if err := c.Identity.Validate(c.Type); err != nil {
		return err
	}
	c.AuthBinding.Normalize()
	if err := c.AuthBinding.Validate(); err != nil {
		return err
	}
	if err := validateUniqueIDs(c.RegistryIDs, ErrInvalidModelPolicy, "registry"); err != nil {
		return err
	}
	if err := c.Fallback.Validate(); err != nil {
		return err
	}
	if err := c.ModelPolicies.Validate(c.knownRegistryIDs()); err != nil {
		return err
	}
	if err := c.LBConfig.ValidateTierRegistries(c.knownRegistryIDs()); err != nil {
		return err
	}
	if err := c.LBConfig.Validate(c.ModelPolicies); err != nil {
		return err
	}
	if err := c.validatePersonal(); err != nil {
		return err
	}
	if c.Type == TypeMCP {
		if c.MCP == nil {
			c.MCP = &MCPPolicy{}
		}
		return c.MCP.Validate(c.knownRegistryIDs())
	}
	return nil
}

// SetLabelSets replaces the consumer's traffic label sets with a trimmed,
// validated copy. Only LLM consumers serve chat routes, so only they can hold
// label sets.
func (c *Consumer) SetLabelSets(sets []trafficlabel.LabelSet) error {
	if len(sets) > 0 && c.Type != TypeLLM {
		return fmt.Errorf("%w: only LLM consumers can hold traffic label sets", ErrInvalidLabelSets)
	}
	normalized := trafficlabel.NormalizeLabelSets(sets)
	if err := trafficlabel.ValidateLabelSets(normalized); err != nil {
		return err
	}
	if len(normalized) == 0 {
		normalized = nil
	}
	c.LabelSets = normalized
	return nil
}

func (c *Consumer) knownRegistryIDs() map[ids.RegistryID]struct{} {
	known := make(map[ids.RegistryID]struct{}, len(c.RegistryIDs))
	for _, id := range c.RegistryIDs {
		known[id] = struct{}{}
	}
	if c.Fallback != nil {
		for _, id := range c.Fallback.Chain {
			known[id] = struct{}{}
		}
	}
	return known
}

type identifier interface {
	comparable
	fmt.Stringer
	IsNil() bool
}

func validateUniqueIDs[T identifier](list []T, invalidErr error, label string) error {
	seen := make(map[T]struct{}, len(list))
	for _, id := range list {
		if id.IsNil() {
			return fmt.Errorf("%w: nil uuid", invalidErr)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: duplicate %s %s", invalidErr, label, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}
