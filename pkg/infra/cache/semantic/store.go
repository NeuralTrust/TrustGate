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

// Package semantic provides a Redis Stack (RediSearch) vector store used by the
// semantic cache plugin to look up and persist responses by embedding
// similarity, scoped per rule via a hashed tag.
package semantic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/redis/go-redis/v9"
)

const (
	defaultIndexName = "semantic_cache"
	keyPrefix        = "semantic_cache:"
	exactKeyPrefix   = "sc_exact:" // #nosec G101 -- redis key prefix, not a credential
)

// Candidate is a cache hit returned by Lookup.
type Candidate struct {
	Response   string
	Similarity float64
}

// Entry is a response to persist for future similarity lookups.
type Entry struct {
	RuleID    string
	Embedding *embedding.Embedding
	Response  string
	TTL       time.Duration
}

// Store is the vector cache backing the semantic cache plugin.
//
//go:generate mockery --name=Store --dir=. --output=./mocks --filename=store_mock.go --case=underscore --with-expecter
type Store interface {
	EnsureIndex(ctx context.Context, dimension int) error
	Lookup(ctx context.Context, ruleID string, emb *embedding.Embedding, topK int) ([]Candidate, error)
	Store(ctx context.Context, entry Entry) error
	GetExact(ctx context.Context, ruleID, key string) (string, bool, error)
	PutExact(ctx context.Context, ruleID, key, response string, ttl time.Duration) error
}

var _ Store = (*RedisStore)(nil)

// RedisStore implements Store against Redis Stack RediSearch.
type RedisStore struct {
	client    *redis.Client
	indexName string
	logger    *slog.Logger

	ensureMu sync.Mutex
	indexed  atomic.Bool
}

// Option customizes a RedisStore.
type Option func(*RedisStore)

// WithIndexName overrides the RediSearch index name.
func WithIndexName(name string) Option {
	return func(s *RedisStore) {
		if name != "" {
			s.indexName = name
		}
	}
}

// NewRedisStore builds a vector store over the given Redis client.
func NewRedisStore(client *redis.Client, logger *slog.Logger, opts ...Option) *RedisStore {
	s := &RedisStore{
		client:    client,
		indexName: defaultIndexName,
		logger:    logger,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// EnsureIndex creates the vector index once, tolerating a pre-existing index.
func (s *RedisStore) EnsureIndex(ctx context.Context, dimension int) error {
	if s.indexed.Load() {
		return nil
	}
	s.ensureMu.Lock()
	defer s.ensureMu.Unlock()
	if s.indexed.Load() {
		return nil
	}

	if err := s.client.Do(ctx, "FT.INFO", s.indexName).Err(); err == nil {
		s.indexed.Store(true)
		return nil
	}

	args := []interface{}{
		"FT.CREATE", s.indexName,
		"ON", "HASH",
		"PREFIX", "1", keyPrefix,
		"SCHEMA",
		"rule_id", "TAG", "SEPARATOR", ",",
		"response", "TEXT", "NOINDEX",
		"embedding", "VECTOR", "FLAT", "6",
		"TYPE", "FLOAT32",
		"DIM", strconv.Itoa(dimension),
		"DISTANCE_METRIC", "COSINE",
	}
	if err := s.client.Do(ctx, args...).Err(); err != nil {
		return fmt.Errorf("semantic: create vector index: %w", err)
	}

	s.indexed.Store(true)
	if s.logger != nil {
		s.logger.Info("semantic vector index created", slog.String("index", s.indexName))
	}
	return nil
}

// Lookup returns the topK nearest cached responses for the rule, ordered by
// descending similarity. A query error degrades to no candidates so the caller
// can fall through to the upstream.
func (s *RedisStore) Lookup(ctx context.Context, ruleID string, emb *embedding.Embedding, topK int) ([]Candidate, error) {
	blob, err := emb.ToBlob()
	if err != nil {
		return nil, fmt.Errorf("semantic: embedding to blob: %w", err)
	}

	hashed := hashID(ruleID)
	query := fmt.Sprintf("(@rule_id:{%s})=>[KNN %d @embedding $BLOB]", hashed, topK)
	args := []interface{}{
		"FT.SEARCH", s.indexName,
		query,
		"PARAMS", "2", "BLOB", blob,
		"RETURN", "2", "response", "__embedding_score",
		"DIALECT", "2",
	}

	result := s.client.Do(ctx, args...)
	if err := result.Err(); err != nil {
		if s.logger != nil {
			s.logger.Debug("semantic cache lookup failed", slog.String("error", err.Error()))
		}
		return nil, nil
	}
	resSlice, err := result.Slice()
	if err != nil {
		return nil, nil
	}
	return parseSearch(resSlice), nil
}

// Store persists a response keyed by its embedding under the rule's tag.
func (s *RedisStore) Store(ctx context.Context, entry Entry) error {
	blob, err := entry.Embedding.ToBlob()
	if err != nil {
		return fmt.Errorf("semantic: embedding to blob: %w", err)
	}

	hashed := hashID(entry.RuleID)
	uniqueID := strconv.FormatInt(time.Now().UnixNano(), 10)
	key := keyPrefix + hashed[:16] + ":" + uniqueID

	pipe := s.client.Pipeline()
	pipe.HSet(ctx, key, map[string]interface{}{
		"embedding": blob,
		"rule_id":   hashed,
		"response":  entry.Response,
	})
	if entry.TTL > 0 {
		pipe.Expire(ctx, key, entry.TTL)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("semantic: store cache entry: %w", err)
	}
	return nil
}

// GetExact returns the response cached under the exact key for the rule. A miss
// or a transient backend error degrades to ("", false, nil) so the caller falls
// through to the upstream, matching Lookup's degrade-on-error contract.
func (s *RedisStore) GetExact(ctx context.Context, ruleID, key string) (string, bool, error) {
	full := exactKeyPrefix + hashID(ruleID) + ":" + key
	val, err := s.client.Get(ctx, full).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("semantic cache exact get failed", slog.String("error", err.Error()))
		}
		return "", false, nil
	}
	return val, true, nil
}

// PutExact stores a response under the exact key for the rule. A TTL of zero or
// less stores the entry without expiry.
func (s *RedisStore) PutExact(ctx context.Context, ruleID, key, response string, ttl time.Duration) error {
	full := exactKeyPrefix + hashID(ruleID) + ":" + key
	if err := s.client.Set(ctx, full, response, ttl).Err(); err != nil {
		return fmt.Errorf("semantic: put exact entry: %w", err)
	}
	return nil
}

// parseSearch converts the raw FT.SEARCH reply into candidates. The reply shape
// is [count, key1, [field, value, ...], key2, [...], ...].
func parseSearch(res []interface{}) []Candidate {
	if len(res) < 2 {
		return nil
	}
	count, ok := res[0].(int64)
	if !ok || count == 0 {
		return nil
	}

	candidates := make([]Candidate, 0, count)
	for i := 1; i+1 < len(res); i += 2 {
		fields, ok := res[i+1].([]interface{})
		if !ok {
			continue
		}
		response, similarity := parseFields(fields)
		if response != "" {
			candidates = append(candidates, Candidate{Response: response, Similarity: similarity})
		}
	}
	return candidates
}

func parseFields(fields []interface{}) (response string, similarity float64) {
	for j := 0; j+1 < len(fields); j += 2 {
		key, ok := fields[j].(string)
		if !ok {
			continue
		}
		value, ok := fields[j+1].(string)
		if !ok {
			continue
		}
		switch key {
		case "response":
			response = value
		case "__embedding_score":
			if score, err := strconv.ParseFloat(value, 64); err == nil {
				similarity = 1.0 - score
			}
		}
	}
	return response, similarity
}

func hashID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
