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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgvectorDimension is the fixed embedding width the pgvector backend supports
// for v1; the column is declared vector(1536), so embeddings of any other width
// degrade to pass-through rather than failing the request.
const pgvectorDimension = 1536

const pgvectorSchemaDDL = `CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS semantic_cache_entries (
	id BIGSERIAL PRIMARY KEY,
	rule_id TEXT NOT NULL,
	embedding vector(1536) NOT NULL,
	response TEXT NOT NULL,
	expires_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS semantic_cache_entries_rule_id_idx ON semantic_cache_entries (rule_id);
CREATE INDEX IF NOT EXISTS semantic_cache_entries_embedding_idx ON semantic_cache_entries USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX IF NOT EXISTS semantic_cache_entries_expires_at_idx ON semantic_cache_entries (expires_at);
CREATE TABLE IF NOT EXISTS semantic_cache_exact (
	rule_id TEXT NOT NULL,
	key TEXT NOT NULL,
	response TEXT NOT NULL,
	expires_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (rule_id, key)
);
CREATE INDEX IF NOT EXISTS semantic_cache_exact_expires_at_idx ON semantic_cache_exact (expires_at);`

var _ Store = (*PgvectorStore)(nil)

// PgvectorStore implements Store against PostgreSQL with the pgvector extension.
// The schema is created lazily on first use so the backend stays inert (and never
// blocks process startup) unless it is the configured vector store.
type PgvectorStore struct {
	pool        *pgxpool.Pool
	logger      *slog.Logger
	schemaReady atomic.Bool
	mu          sync.Mutex
}

// NewPgvectorStore builds a vector store over the given pgx pool.
func NewPgvectorStore(pool *pgxpool.Pool, logger *slog.Logger) *PgvectorStore {
	return &PgvectorStore{pool: pool, logger: logger}
}

// EnsureIndex validates the requested dimension. A dimension other than the
// supported width is rejected so the plugin degrades to pass-through. Schema
// creation is deferred to the first data operation via ensureSchema.
func (s *PgvectorStore) EnsureIndex(ctx context.Context, dimension int) error {
	if dimension != pgvectorDimension {
		return fmt.Errorf("semantic: pgvector supports dimension %d, got %d", pgvectorDimension, dimension)
	}
	return nil
}

func (s *PgvectorStore) ensureSchema(ctx context.Context) error {
	if s.schemaReady.Load() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.schemaReady.Load() {
		return nil
	}
	if s.pool == nil {
		return errors.New("semantic: pgvector store has no database pool")
	}
	if _, err := s.pool.Exec(ctx, pgvectorSchemaDDL); err != nil {
		return fmt.Errorf("semantic: ensure pgvector schema: %w", err)
	}
	s.schemaReady.Store(true)
	return nil
}

// Lookup returns the topK nearest cached responses for the rule, ordered by
// descending cosine similarity. Any query error degrades to no candidates so the
// caller falls through to the upstream.
func (s *PgvectorStore) Lookup(ctx context.Context, ruleID string, emb *embedding.Embedding, topK int) ([]Candidate, error) {
	if emb == nil || topK <= 0 {
		return nil, nil
	}
	if err := s.ensureSchema(ctx); err != nil {
		s.debug("semantic cache schema unavailable", err)
		return nil, nil
	}
	literal := vectorLiteral(emb.Value)

	const query = `SELECT response, 1 - (embedding <=> $1::vector) AS similarity
FROM semantic_cache_entries
WHERE rule_id = $2 AND (expires_at IS NULL OR expires_at > now())
ORDER BY embedding <=> $1::vector
LIMIT $3`

	rows, err := s.pool.Query(ctx, query, literal, hashID(ruleID), topK)
	if err != nil {
		s.debug("semantic cache lookup failed", err)
		return nil, nil
	}
	defer rows.Close()

	candidates := make([]Candidate, 0, topK)
	for rows.Next() {
		var (
			response   string
			similarity float64
		)
		if err := rows.Scan(&response, &similarity); err != nil {
			s.debug("semantic cache lookup scan failed", err)
			return nil, nil
		}
		candidates = append(candidates, Candidate{Response: response, Similarity: similarity})
	}
	if err := rows.Err(); err != nil {
		s.debug("semantic cache lookup iteration failed", err)
		return nil, nil
	}
	return candidates, nil
}

// Store persists a response keyed by its embedding under the rule. An embedding
// whose width is not the supported dimension degrades to a no-op.
func (s *PgvectorStore) Store(ctx context.Context, entry Entry) error {
	if entry.Embedding == nil || len(entry.Embedding.Value) != pgvectorDimension {
		s.debugMsg("semantic cache store skipped: unsupported embedding dimension")
		return nil
	}
	if err := s.ensureSchema(ctx); err != nil {
		s.debug("semantic cache schema unavailable", err)
		return nil
	}
	literal := vectorLiteral(entry.Embedding.Value)

	var expiresAt *time.Time
	if entry.TTL > 0 {
		t := time.Now().Add(entry.TTL)
		expiresAt = &t
	}

	const query = `INSERT INTO semantic_cache_entries (rule_id, embedding, response, expires_at, created_at)
VALUES ($1, $2::vector, $3, $4, now())`

	if _, err := s.pool.Exec(ctx, query, hashID(entry.RuleID), literal, entry.Response, expiresAt); err != nil {
		return fmt.Errorf("semantic: store cache entry: %w", err)
	}
	return nil
}

// GetExact returns the response cached under the exact key for the rule. A miss
// or a transient backend error degrades to ("", false, nil) so the caller falls
// through to the upstream.
func (s *PgvectorStore) GetExact(ctx context.Context, ruleID, key string) (string, bool, error) {
	if err := s.ensureSchema(ctx); err != nil {
		s.debug("semantic cache schema unavailable", err)
		return "", false, nil
	}
	const query = `SELECT response FROM semantic_cache_exact
WHERE rule_id = $1 AND key = $2 AND (expires_at IS NULL OR expires_at > now())`

	var response string
	err := s.pool.QueryRow(ctx, query, hashID(ruleID), key).Scan(&response)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		s.debug("semantic cache exact get failed", err)
		return "", false, nil
	}
	return response, true, nil
}

// PutExact stores a response under the exact key for the rule. A TTL of zero or
// less stores the entry without expiry.
func (s *PgvectorStore) PutExact(ctx context.Context, ruleID, key, response string, ttl time.Duration) error {
	if err := s.ensureSchema(ctx); err != nil {
		s.debug("semantic cache schema unavailable", err)
		return nil
	}
	var expiresAt *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expiresAt = &t
	}

	const query = `INSERT INTO semantic_cache_exact (rule_id, key, response, expires_at, created_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (rule_id, key) DO UPDATE SET response = EXCLUDED.response, expires_at = EXCLUDED.expires_at`

	if _, err := s.pool.Exec(ctx, query, hashID(ruleID), key, response, expiresAt); err != nil {
		return fmt.Errorf("semantic: put exact entry: %w", err)
	}
	return nil
}

func (s *PgvectorStore) debug(msg string, err error) {
	if s.logger != nil {
		s.logger.Debug(msg, slog.String("error", err.Error()))
	}
}

func (s *PgvectorStore) debugMsg(msg string) {
	if s.logger != nil {
		s.logger.Debug(msg)
	}
}

// vectorLiteral renders a float slice as a pgvector text literal "[v1,v2,...]".
func vectorLiteral(values []float64) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	}
	b.WriteByte(']')
	return b.String()
}
