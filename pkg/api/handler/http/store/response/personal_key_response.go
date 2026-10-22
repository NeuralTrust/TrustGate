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

package response

import (
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// PersonalKeyResponse is one of the caller's keys without its secret: their
// personal key, or a key held for one of their groups.
type PersonalKeyResponse struct {
	ID          ids.AuthID       `json:"id"`
	ConsumerIDs []ids.ConsumerID `json:"consumer_ids"`
	KeyPrefix   string           `json:"key_prefix"`
	KeySuffix   string           `json:"key_suffix"`
	ExpiresAt   *time.Time       `json:"expires_at"`
	Enabled     bool             `json:"enabled"`
	// GroupID and GroupName name the directory group a group key is held for.
	// Both are absent on the personal key.
	GroupID   string    `json:"group_id,omitempty"`
	GroupName string    `json:"group_name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FromPersonalKey maps a personal key, listing its consumers as an empty array
// rather than null when it has none.
func FromPersonalKey(key *appauth.PersonalKey) PersonalKeyResponse {
	consumerIDs := key.ConsumerIDs
	if consumerIDs == nil {
		consumerIDs = []ids.ConsumerID{}
	}
	return PersonalKeyResponse{
		ID:          key.Auth.ID,
		ConsumerIDs: consumerIDs,
		KeyPrefix:   key.Auth.KeyPrefix,
		KeySuffix:   key.Auth.KeySuffix,
		ExpiresAt:   key.Auth.ExpiresAt,
		Enabled:     key.Auth.Enabled,
		GroupID:     key.Auth.GroupID,
		GroupName:   key.Auth.GroupName,
		CreatedAt:   key.Auth.CreatedAt,
		UpdatedAt:   key.Auth.UpdatedAt,
	}
}

// PersonalKeyListResponse is every key the caller holds on the gateway,
// newest first.
type PersonalKeyListResponse struct {
	Items []PersonalKeyResponse `json:"items"`
}

// FromPersonalKeys maps the caller's keys, an empty list rather than null when
// they hold none.
func FromPersonalKeys(keys []*appauth.PersonalKey) PersonalKeyListResponse {
	out := PersonalKeyListResponse{Items: make([]PersonalKeyResponse, 0, len(keys))}
	for _, key := range keys {
		out.Items = append(out.Items, FromPersonalKey(key))
	}
	return out
}
