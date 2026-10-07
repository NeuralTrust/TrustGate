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
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

func TestDefaultIdPAdmitted(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	store := domain.BuildStoreConsumer(gw)
	ordinary := &domain.Consumer{GatewayID: gw}
	auth := func(typ authdomain.Type, enabled bool) *authdomain.Auth {
		return &authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: typ, Enabled: enabled}
	}

	tests := []struct {
		name    string
		matches []appconsumer.PathMatch
		want    bool
	}{
		{name: "store with nothing attached", matches: []appconsumer.PathMatch{{Consumer: store}}, want: true},
		{name: "store with a disabled api key", matches: []appconsumer.PathMatch{{Consumer: store, Auths: []*authdomain.Auth{auth(authdomain.TypeAPIKey, false)}}}, want: true},
		{name: "store with an enabled api key", matches: []appconsumer.PathMatch{{Consumer: store, Auths: []*authdomain.Auth{auth(authdomain.TypeAPIKey, true)}}}},
		{name: "store with a disabled oauth2 auth", matches: []appconsumer.PathMatch{{Consumer: store, Auths: []*authdomain.Auth{auth(authdomain.TypeOAuth2, false)}}}},
		{name: "ordinary consumer with nothing attached", matches: []appconsumer.PathMatch{{Consumer: ordinary}}},
		{name: "nil consumer", matches: []appconsumer.PathMatch{{}}},
		{name: "no matches"},
		{name: "store beside a consumer with a credential", matches: []appconsumer.PathMatch{
			{Consumer: store},
			{Consumer: ordinary, Auths: []*authdomain.Auth{auth(authdomain.TypeAPIKey, true)}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, appconsumer.DefaultIdPAdmitted(tt.matches))
		})
	}
}
