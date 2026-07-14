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

package cache

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

const vectorDimension = 1536

type (
	RedisIndexCreator interface {
		CreateIndexes(ctx context.Context, keys ...string) error
	}
	redisIndexCreator struct {
		redis  *redis.Client
		logger *slog.Logger
	}
)

func NewRedisIndexCreator(redis *redis.Client, logger *slog.Logger) RedisIndexCreator {
	return &redisIndexCreator{
		redis:  redis,
		logger: logger,
	}
}

func (c *redisIndexCreator) CreateIndexes(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		dropArgs := []interface{}{"FT.DROPINDEX", key, "DD"}
		if err := c.redis.Do(ctx, dropArgs...).Err(); err != nil &&
			!strings.Contains(err.Error(), "Unknown Index name") {
			c.logger.Warn("failed to drop index",
				slog.String("index", key),
				slog.String("error", err.Error()),
			)
		}

		args := []interface{}{
			"FT.CREATE", key,
			"ON", "HASH",
			"PREFIX", "1", key + ":",
			"SCHEMA",
			"gateway_id", "TAG", "SEPARATOR", ",",
			"data", "TAG", "SEPARATOR", "|",
			"embedding", "VECTOR", "FLAT", "6",
			"TYPE", "FLOAT32",
			"DIM", strconv.Itoa(vectorDimension),
			"DISTANCE_METRIC", "COSINE",
		}

		if err := c.redis.Do(ctx, args...).Err(); err != nil {
			c.logger.Error("failed to create vector index",
				slog.String("index", key),
				slog.String("error", err.Error()),
			)
			return err
		}

		c.logger.Info("vector index created successfully", slog.String("index", key))
	}

	return nil
}
