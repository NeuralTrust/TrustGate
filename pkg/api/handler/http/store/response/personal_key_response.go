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

type PersonalKeyResponse struct {
	ID          ids.AuthID       `json:"id"`
	ConsumerIDs []ids.ConsumerID `json:"consumer_ids"`
	KeyPrefix   string           `json:"key_prefix"`
	KeySuffix   string           `json:"key_suffix"`
	ExpiresAt   *time.Time       `json:"expires_at"`
	Enabled     bool             `json:"enabled"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

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
		CreatedAt:   key.Auth.CreatedAt,
		UpdatedAt:   key.Auth.UpdatedAt,
	}
}
