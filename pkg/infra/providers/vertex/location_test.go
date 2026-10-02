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

package vertex

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var hostileLocations = []string{
	"10.0.0.5:8081/",
	"evil.example/",
	"evil.example",
	"a.b",
	"us-central1/x",
	"host:80",
	"user@evil",
	"evil#",
	"evil?x=1",
	"evil%2f",
	"us central1",
	"-us",
	"1us",
}

func TestDecodeVertexOptionsLocation(t *testing.T) {
	for _, loc := range []string{"us-central1", "europe-west4", "asia-northeast1", "northamerica-northeast1", "global", "us", "eu", "US-CENTRAL1"} {
		t.Run("accepts "+loc, func(t *testing.T) {
			_, err := providers.DecodeVertexOptions(map[string]any{"project": "p", "location": loc})
			require.NoError(t, err)
		})
	}
	for _, loc := range hostileLocations {
		t.Run("rejects "+loc, func(t *testing.T) {
			_, err := providers.DecodeVertexOptions(map[string]any{"project": "p", "location": loc})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "location")
		})
	}
}

// A hostile location must fail before any connection is made, because the
// request carries a cloud-platform bearer token.
func TestEmbeddingsHostileLocationNeverConnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	var accepts atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = conn.Close()
		}
	}()

	c := NewVertexClient().(providers.EmbeddingsClient)
	_, err = c.Embeddings(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "tok"},
		Model:       "text-embedding-004",
		Options:     map[string]any{"project": "p", "location": ln.Addr().String() + "/"},
	}, []byte(`{"content":{"parts":[{"text":"hi"}]}}`))

	require.Error(t, err)
	assert.Zero(t, accepts.Load(), "the gateway must never connect to a host taken from location")
}
