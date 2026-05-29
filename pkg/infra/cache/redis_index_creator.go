package cache

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/go-redis/redis/v8"
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
