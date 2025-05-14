package cache

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

const vectorDimension = 1536

type (
	RedisIndexCreator interface {
		CreateIndexes(ctx context.Context, keys ...string) error
	}
	redisIndexCreator struct {
		redis  *redis.Client
		logger *logrus.Logger
	}
)

func NewRedisIndexCreator(redis *redis.Client, logger *logrus.Logger) RedisIndexCreator {
	return &redisIndexCreator{
		redis:  redis,
		logger: logger,
	}
}

func (c *redisIndexCreator) CreateIndexes(ctx context.Context, keys ...string) error {

	moduleListCmd := c.redis.Do(ctx, "MODULE", "LIST")
	if moduleListCmd.Err() != nil {
		c.logger.WithError(moduleListCmd.Err()).Warn("failed to list Redis modules")
		return moduleListCmd.Err()
	}

	modules, ok := moduleListCmd.Val().([]interface{})
	if !ok {
		c.logger.Warn("failed to parse Redis modules list")
		return fmt.Errorf("failed to parse Redis modules list")
	}

	redisSearchAvailable := false
	for _, module := range modules {
		info, ok := module.([]interface{})
		if !ok || len(info) < 2 {
			continue
		}

		name, ok := info[1].(string)
		if ok && (name == "search" || name == "redisearch") {
			redisSearchAvailable = true
			break
		}
	}

	if !redisSearchAvailable {
		c.logger.Warn("redisSearch module is not available")
		return fmt.Errorf("RedisSearch module not found")
	}

	c.logger.Info("redisSearch module found, creating indexes...")

	for _, key := range keys {
		dropArgs := []interface{}{"FT.DROPINDEX", key, "DD"}
		err := c.redis.Do(ctx, dropArgs...).Err()
		if err != nil && !strings.Contains(err.Error(), "Unknown Index name") {
			c.logger.WithError(err).Warnf("Failed to drop index %s", key)
		}

		args := []interface{}{
			"FT.CREATE", key,
			"ON", "HASH",
			"PREFIX", "1", key + ":",
			"SCHEMA",
			"gateway_id", "TAG", "SEPARATOR", ",",
			"data", "TEXT",
			"embedding", "VECTOR", "FLAT", "6",
			"TYPE", "FLOAT32",
			"DIM", strconv.Itoa(vectorDimension),
			"DISTANCE_METRIC", "COSINE",
		}

		err = c.redis.Do(ctx, args...).Err()
		if err != nil {
			c.logger.WithError(err).Errorf("Failed to create vector index: %s", key)
			return err
		}

		c.logger.Infof("Vector index created successfully: %s", key)
	}

	return nil
}
