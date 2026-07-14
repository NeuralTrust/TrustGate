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

package semantic

import (
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	t.Cleanup(func() { _ = client.Close() })

	tests := []struct {
		name    string
		kind    string
		deps    Deps
		wantErr bool
		assert  func(t *testing.T, store Store)
	}{
		{
			name: "empty defaults to redis",
			kind: "",
			deps: Deps{Redis: client},
			assert: func(t *testing.T, store Store) {
				assert.IsType(t, &RedisStore{}, store)
			},
		},
		{
			name: "redis",
			kind: "redis",
			deps: Deps{Redis: client},
			assert: func(t *testing.T, store Store) {
				assert.IsType(t, &RedisStore{}, store)
			},
		},
		{
			name: "redis without client builds a lazy store",
			kind: "redis",
			deps: Deps{},
			assert: func(t *testing.T, store Store) {
				assert.IsType(t, &RedisStore{}, store)
			},
		},
		{
			name: "in_memory",
			kind: "in_memory",
			deps: Deps{},
			assert: func(t *testing.T, store Store) {
				assert.IsType(t, &MemoryStore{}, store)
			},
		},
		{
			name:    "pgvector without pool errors",
			kind:    "pgvector",
			deps:    Deps{},
			wantErr: true,
		},
		{
			name:    "unknown kind errors",
			kind:    "elasticsearch",
			deps:    Deps{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := NewStore(tt.kind, tt.deps)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, store)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, store)
			tt.assert(t, store)
		})
	}
}
