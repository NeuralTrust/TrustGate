package cache

import (
	"context"
	"fmt"
	"strconv"

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
	fmt.Println("creating redis indexes")
	moduleListCmd := c.redis.Do(ctx, "MODULE", "LIST")
	if moduleListCmd.Err() != nil {
		c.logger.WithError(moduleListCmd.Err()).Warn("failed to list Redis modules")
		return nil
	}

	// Parse the module list to check if RediSearch is available
	modules, ok := moduleListCmd.Val().([]interface{})
	if !ok {
		c.logger.Warn("failed to parse Redis modules list")
		return nil
	}

	redisSearchAvailable := false
	for _, module := range modules {
		moduleInfo, ok := module.([]interface{})
		if !ok || len(moduleInfo) < 2 {
			continue
		}

		moduleName, ok := moduleInfo[1].(string)
		if !ok {
			continue
		}

		if moduleName == "search" || moduleName == "redisearch" {
			redisSearchAvailable = true
			break
		}
	}

	if !redisSearchAvailable {
		fmt.Println("redis search module is not available")
		c.logger.Warn("redis search module is not available. vector search functionality will be disabled.")
		return nil
	}

	for _, key := range keys {
		dropArgs := []interface{}{
			"FT.DROPINDEX", key,
		}
		err := c.redis.Do(ctx, dropArgs...).Err()
		if err != nil {
			c.logger.WithError(err).Warn("failed to drop index %s", key)
		}

		args := []interface{}{
			"FT.CREATE", key,
			"ON", "HASH",
			"PREFIX", "1", key + ":",
			"SCHEMA",
			"rule_id", "TAG",
			"response", "TEXT",
			"embedding", "VECTOR", "FLAT", "6",
			"TYPE", "FLOAT32",
			"DIM", strconv.Itoa(vectorDimension),
			"DISTANCE_METRIC", "COSINE",
		}
		err = c.redis.Do(ctx, args...).Err()
		if err != nil {
			c.logger.WithError(err).Error("failed to create vector index")
			return err
		}
		c.logger.Info("vector index created successfully: " + key)
	}
	return nil
}
