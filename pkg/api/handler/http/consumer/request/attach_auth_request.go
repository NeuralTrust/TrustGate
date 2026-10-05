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

package request

import (
	"fmt"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

// AttachAuthRequest carries the optional link attributes of an auth attach.
type AttachAuthRequest struct {
	Level     *string `json:"level,omitempty" enums:"user,group,all" example:"group"`
	Priority  *int    `json:"priority,omitempty" minimum:"0" maximum:"2147483647" example:"1"`
	GrantedAt *string `json:"granted_at,omitempty" format:"date-time" example:"2026-10-01T09:00:00Z"`
}

// ToLink returns nil when no attribute is present and otherwise the link with
// priority defaulted to 1, leaving its validation to the domain.
func (r AttachAuthRequest) ToLink() (*domain.AuthLink, error) {
	if r.Level == nil && r.Priority == nil && r.GrantedAt == nil {
		return nil, nil
	}
	link := domain.AuthLink{Priority: domain.DefaultGrantPriority}
	if r.Level != nil {
		link.Level = domain.GrantLevel(*r.Level)
	}
	if r.Priority != nil {
		link.Priority = *r.Priority
	}
	if r.GrantedAt != nil {
		grantedAt, err := time.Parse(time.RFC3339, *r.GrantedAt)
		if err != nil {
			return nil, fmt.Errorf("%w: granted_at must be an RFC 3339 instant", domain.ErrInvalidAuthLink)
		}
		link.GrantedAt = grantedAt.UTC()
	}
	return &link, nil
}
