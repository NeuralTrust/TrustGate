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

package oauth_test

import (
	"context"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/clustertest"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
)

func TestConnectStoreHasDynamicClientMatchesCodeBoundary(t *testing.T) {
	store, _ := newConnectStore(t)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	const code = "com.vercel/mcp"
	require.NoError(t, store.SaveClient(ctx, gw.String()+"|"+code+"2|fp", appoauth.RegisteredClient{ClientID: "other"}))
	found, err := store.HasDynamicClient(ctx, gw, code)
	require.NoError(t, err)
	require.False(t, found)

	require.NoError(t, store.SaveClient(ctx, gw.String()+"|"+code+"|fp|server", appoauth.RegisteredClient{ClientID: "dyn"}))
	found, err = store.HasDynamicClient(ctx, gw, code)
	require.NoError(t, err)
	require.True(t, found)
}

func TestConnectStoreHasDynamicClientScansEveryClusterMaster(t *testing.T) {
	server := miniredis.RunT(t)
	client := clustertest.NewCluster(server.Addr())
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	store := infraoauth.NewConnectStore(client)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	const code = "com.vercel/mcp"

	found, err := store.HasDynamicClient(ctx, gw, code)
	require.NoError(t, err)
	require.False(t, found)

	require.NoError(t, store.SaveClient(ctx, gw.String()+"|"+code+"|fp|server", appoauth.RegisteredClient{ClientID: "dyn"}))
	found, err = store.HasDynamicClient(ctx, gw, code)
	require.NoError(t, err)
	require.True(t, found)
}
