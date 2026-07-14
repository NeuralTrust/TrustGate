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
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Deps carries the backend handles a Store may need; only the field matching
// the selected kind is required.
type Deps struct {
	Redis  *redis.Client
	Pool   *pgxpool.Pool
	Logger *slog.Logger
}

// NewStore builds the Store backend named by kind. An empty kind defaults to
// redis, preserving the historical behaviour.
func NewStore(kind string, deps Deps) (Store, error) {
	switch kind {
	case "", "redis":
		return NewRedisStore(deps.Redis, deps.Logger), nil
	case "in_memory":
		return NewMemoryStore(deps.Logger), nil
	case "pgvector":
		if deps.Pool == nil {
			return nil, fmt.Errorf("semantic: pgvector store requires a database pool")
		}
		return NewPgvectorStore(deps.Pool, deps.Logger), nil
	default:
		return nil, fmt.Errorf("semantic: unknown vector_store %q", kind)
	}
}
