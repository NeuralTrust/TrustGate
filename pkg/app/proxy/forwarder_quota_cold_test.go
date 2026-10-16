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

package proxy_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	ratelimitinfra "github.com/NeuralTrust/TrustGate/pkg/infra/ratelimit"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fixedPlan is the entitlements lookup for one gateway.
type fixedPlan struct {
	resolved ratelimitapp.Resolved
}

func (f fixedPlan) Resolve(context.Context, ids.GatewayID) (ratelimitapp.Resolved, error) {
	return f.resolved, nil
}

// An org whose monthly quota is already spent, and whose pod has no counter
// for it, must be rejected on that request. The provider is not called.
func TestForward_ExhaustedQuotaWithMissingCounterDoesNotCallProvider(t *testing.T) {
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	const quotaKey = "gt:rl:quota:{acme}:2026-10"
	require.NoError(t, mr.Set(quotaKey, "100000"))

	when := time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)
	gatewayID := ids.New[ids.GatewayKind]()
	meter := ratelimitapp.NewMeter(fixedPlan{resolved: ratelimitapp.Resolved{
		Subject: "acme",
		Limits:  ratelimitdomain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000},
	}}, ratelimitinfra.NewStore(rc, newTestLogger()), ratelimitapp.Options{
		Now: func() time.Time { return when },
	}, newTestLogger())

	invoker := proxymocks.NewProviderInvoker(t)
	fwd := newTestForwarderWithLimiter(t, invoker, meter)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  routableConsumerWith(gatewayID),
		Request: &infracontext.RequestContext{
			SourceFormat:    "openai",
			ProxyCapability: "chat",
			Body:            []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
	assert.Equal(t, []string{"application/json"}, res.Headers["Content-Type"])
	assert.Equal(t, []string{ratelimitapp.ReasonQuota}, res.Headers["X-RateLimit-Reason"])
	assert.Equal(t, []string{"100000"}, res.Headers["X-RateLimit-Limit"])
	assert.Equal(t, []string{"0"}, res.Headers["X-RateLimit-Remaining"])
	assert.NotEmpty(t, res.Headers["Retry-After"])
	assert.Contains(t, string(res.Body), "monthly request quota exceeded")
	invoker.AssertNotCalled(t, "Invoke", mock.Anything, mock.Anything, mock.Anything)

	got, err := mr.Get(quotaKey)
	require.NoError(t, err)
	assert.Equal(t, "100000", got, "the rejected completion is not usage")
}
