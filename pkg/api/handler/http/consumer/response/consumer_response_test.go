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

package response_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer/response"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

func TestFromConsumer_PersonalListsAuthIDsWithoutLinks(t *testing.T) {
	t.Parallel()
	authIDs := make([]ids.AuthID, 500)
	links := make(map[ids.AuthID]domain.AuthLink, len(authIDs))
	for i := range authIDs {
		authIDs[i] = ids.New[ids.AuthKind]()
		links[authIDs[i]] = domain.AuthLink{Level: domain.GrantLevelUser, Priority: i, GrantedAt: time.Date(2026, time.October, 1, 9, 0, 0, 0, time.UTC)}
	}
	personal := domain.Rehydrate(domain.RehydrateParams{
		ID: ids.New[ids.ConsumerKind](), GatewayID: ids.New[ids.GatewayKind](), Name: "personal", Type: domain.TypeLLM,
		Audience: domain.AudiencePersonal, AuthIDs: authIDs, AuthLinks: links,
	})

	raw, err := json.Marshal(response.FromConsumer(personal))
	require.NoError(t, err)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &body))
	require.NotContains(t, body, "auth_links")
	var got []ids.AuthID
	require.NoError(t, json.Unmarshal(body["auth_ids"], &got))
	require.Equal(t, authIDs, got)
	require.JSONEq(t, `"personal"`, string(body["audience"]))
}
