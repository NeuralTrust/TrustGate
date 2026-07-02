package configsync

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

const (
	versionField      = "version"
	streamStart       = "0"
	defaultWatchBlock = 5 * time.Second
)

type RedisStreamNotifier struct {
	client *redis.Client
	stream string
	maxLen int64
	block  time.Duration
}

func NewRedisStreamNotifier(client *redis.Client, stream string, maxLen int64) *RedisStreamNotifier {
	return &RedisStreamNotifier{client: client, stream: stream, maxLen: maxLen, block: defaultWatchBlock}
}

func (n *RedisStreamNotifier) Tail(ctx context.Context) (string, error) {
	entries, err := n.client.XRevRangeN(ctx, n.stream, "+", "-", 1).Result()
	if err != nil {
		return "", fmt.Errorf("configsync: tail stream: %w", err)
	}
	if len(entries) == 0 {
		return streamStart, nil
	}
	return entries[0].ID, nil
}

func (n *RedisStreamNotifier) Watch(ctx context.Context, lastID string) (string, string, error) {
	if lastID == "" {
		lastID = streamStart
	}
	res, err := n.client.XRead(ctx, &redis.XReadArgs{
		Streams: []string{n.stream, lastID},
		Count:   1,
		Block:   n.block,
	}).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("configsync: watch stream: %w", err)
	}
	for _, stream := range res {
		for _, msg := range stream.Messages {
			version, _ := msg.Values[versionField].(string)
			return msg.ID, version, nil
		}
	}
	return "", "", nil
}

func (n *RedisStreamNotifier) Publish(ctx context.Context, version string) (string, error) {
	id, err := n.client.XAdd(ctx, &redis.XAddArgs{
		Stream: n.stream,
		MaxLen: n.maxLen,
		Approx: true,
		Values: map[string]interface{}{versionField: version},
	}).Result()
	if err != nil {
		return "", fmt.Errorf("configsync: publish version: %w", err)
	}
	return id, nil
}
