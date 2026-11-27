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

package trustguard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const strayUserToken = "test-user-token"

// A stray end user token header is never sent to TrustGuard: not as assets.user, not in original_request.headers,
// not anywhere in the body, on v1 or v2.
func TestStrayUserTokenHeaderNeverReachesTrustGuard(t *testing.T) {
	t.Parallel()
	headers := map[string][]string{
		"x-neuraltrust-user-token": {strayUserToken},
		"User-Agent":               {"client/1.0"},
	}
	req := requestContext()
	req.Headers = headers
	ctx := requestmeta.NewContext(context.Background(), "203.0.113.42", headers)
	ctx = trace.NewContext(ctx, trace.New("t-1", trace.Metadata{GatewayID: "gw-test"}))

	t.Run("v2", func(t *testing.T) {
		t.Parallel()
		f := &fakeV2Engine{}
		p := newV2TestPlugin(t, newV2Engine(t, f).URL)
		_, err := p.Execute(ctx, execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), req, nil))
		require.NoError(t, err)

		seen := f.seen()
		require.Len(t, seen, 1)
		assert.NotContains(t, seen[0].Assets, "user", "the token alone is not a user")
		require.NotNil(t, seen[0].OriginalRequest)
		assert.Equal(t, map[string][]string{"User-Agent": {"client/1.0"}}, seen[0].OriginalRequest.Headers)
		raw, err := json.Marshal(seen[0])
		require.NoError(t, err)
		assert.NotContains(t, string(raw), strayUserToken)
	})
	t.Run("v1", func(t *testing.T) {
		t.Parallel()
		f := &fakeGuard{}
		p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
		_, err := p.Execute(ctx, execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
		require.NoError(t, err)
		assert.Zero(t, f.lastBody.Attributes.User)
		raw, err := json.Marshal(f.lastBody)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), strayUserToken)
	})
}
