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

package consumer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

const storeRawKey = "ag_alice"

var storeKeyNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func personalKey(gatewayID ids.GatewayID) *authdomain.Auth {
	expiry := storeKeyNow.Add(time.Hour)
	return &authdomain.Auth{
		ID: ids.New[ids.AuthKind](), GatewayID: gatewayID, Type: authdomain.TypeAPIKey, Enabled: true,
		KeyHash: authdomain.HashAPIKey(storeRawKey), OwnerID: "alice", ExpiresAt: &expiry,
	}
}

func TestStoreKeyResolver_Resolve(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	down := errors.New("database unavailable")
	rejected := appconsumer.ErrStoreKeyRejected
	cases := map[string]struct {
		raw    string
		key    func(*authdomain.Auth)
		lookup error
		want   error
	}{
		"enabled personal key of the gateway": {raw: storeRawKey},
		"empty key without a lookup":          {want: rejected},
		"unknown":                             {raw: storeRawKey, lookup: authdomain.ErrNotFound, want: rejected},
		"expired at lookup":                   {raw: storeRawKey, lookup: authdomain.ErrExpired, want: rejected},
		"expired at now":                      {raw: storeRawKey, key: func(a *authdomain.Auth) { a.ExpiresAt = &storeKeyNow }, want: rejected},
		"disabled":                            {raw: storeRawKey, key: func(a *authdomain.Auth) { a.Enabled = false }, want: rejected},
		"unowned application key":             {raw: storeRawKey, key: func(a *authdomain.Auth) { a.OwnerID = "" }, want: rejected},
		"another gateway":                     {raw: storeRawKey, key: func(a *authdomain.Auth) { a.GatewayID = ids.New[ids.GatewayKind]() }, want: rejected},
		"not an api key":                      {raw: storeRawKey, key: func(a *authdomain.Auth) { a.Type = authdomain.TypeOAuth2 }, want: rejected},
		"hash of another secret":              {raw: storeRawKey, key: func(a *authdomain.Auth) { a.KeyHash = authdomain.HashAPIKey("ag_other") }, want: rejected},
		"lookup failure":                      {raw: storeRawKey, lookup: down, want: down},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key := personalKey(gatewayID)
			if tc.key != nil {
				tc.key(key)
			}
			finder := appauthmocks.NewAPIKeyFinder(t)
			if tc.lookup != nil {
				finder.EXPECT().FindByAPIKey(context.Background(), tc.raw).Return(nil, tc.lookup).Once()
			} else if tc.raw != "" {
				finder.EXPECT().FindByAPIKey(context.Background(), tc.raw).Return(key, nil).Once()
			}

			got, err := appconsumer.NewStoreKeyResolver(finder, func() time.Time { return storeKeyNow }).
				Resolve(context.Background(), gatewayID, tc.raw)

			if tc.want == nil {
				require.NoError(t, err)
				require.Same(t, key, got)
				return
			}
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, got)
			require.Equal(t, tc.want == rejected, errors.Is(err, rejected))
		})
	}
}
