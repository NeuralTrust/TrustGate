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

package policy

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type Policy struct {
	ID          ids.PolicyID     `json:"id"`
	GatewayID   ids.GatewayID    `json:"gateway_id"`
	ConsumerIDs []ids.ConsumerID `json:"consumer_ids,omitempty"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Slug        string           `json:"slug"`
	Enabled     bool             `json:"enabled"`
	Global      bool             `json:"global"`
	Priority    int              `json:"priority"`
	Parallel    bool             `json:"parallel"`
	Settings    map[string]any   `json:"settings,omitempty"`
	Stages      []Stage          `json:"stages,omitempty"`
	Mode        Mode             `json:"mode"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

func (p *Policy) IsGlobal() bool {
	return p.Global
}

func NewPolicy(
	gatewayID ids.GatewayID,
	name string,
	slug string,
	enabled bool,
	priority int,
	parallel bool,
	settings map[string]any,
	stages []Stage,
	description string,
	mode Mode,
) (*Policy, error) {
	id, err := ids.NewV7[ids.PolicyKind]()
	if err != nil {
		return nil, fmt.Errorf("policy: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	p := &Policy{
		ID:          id,
		GatewayID:   gatewayID,
		Name:        name,
		Description: description,
		Slug:        slug,
		Enabled:     enabled,
		Priority:    priority,
		Parallel:    parallel,
		Settings:    settings,
		Stages:      stages,
		Mode:        mode.Normalize(),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func Rehydrate(
	id ids.PolicyID,
	gatewayID ids.GatewayID,
	consumerIDs []ids.ConsumerID,
	name string,
	description string,
	slug string,
	enabled bool,
	global bool,
	priority int,
	parallel bool,
	settings map[string]any,
	stages []Stage,
	mode Mode,
	createdAt, updatedAt time.Time,
) *Policy {
	return &Policy{
		ID:          id,
		GatewayID:   gatewayID,
		ConsumerIDs: consumerIDs,
		Name:        name,
		Description: description,
		Slug:        slug,
		Enabled:     enabled,
		Global:      global,
		Priority:    priority,
		Parallel:    parallel,
		Settings:    settings,
		Stages:      stages,
		Mode:        mode.Normalize(),
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

func (p *Policy) Validate() error {
	if p.Name == "" {
		return ErrInvalidName
	}
	if p.Slug == "" {
		return ErrInvalidSlug
	}
	if p.GatewayID.IsNil() {
		return ErrInvalidGatewayID
	}
	if p.Priority < 0 {
		return fmt.Errorf("%w: priority cannot be negative", ErrInvalidPriority)
	}
	seen := make(map[ids.ConsumerID]struct{}, len(p.ConsumerIDs))
	for _, cid := range p.ConsumerIDs {
		if cid.IsNil() {
			return fmt.Errorf("%w: nil consumer_id", ErrInvalidConsumerID)
		}
		if _, dup := seen[cid]; dup {
			return fmt.Errorf("%w: duplicate consumer_id %s", ErrInvalidConsumerID, cid)
		}
		seen[cid] = struct{}{}
	}
	for _, s := range p.Stages {
		if !s.IsValid() {
			return fmt.Errorf("%w: %q", ErrInvalidStage, s)
		}
	}
	if p.Mode != "" && !p.Mode.IsValid() {
		return fmt.Errorf("%w: %q", ErrInvalidMode, p.Mode)
	}
	return nil
}
