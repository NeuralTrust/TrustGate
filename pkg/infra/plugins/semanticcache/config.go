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

package semanticcache

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	defaultSimilarityThreshold = 0.85
	defaultTTLSeconds          = 86400
	defaultProvider            = "openai"
	defaultModel               = "text-embedding-ada-002"

	modeExact    = "exact"
	modeSemantic = "semantic"
	modeBoth     = "both"

	scopeConsumer = "consumer"
	scopeGlobal   = "global"

	storeRedis    = "redis"
	storePgvector = "pgvector"
	storeInMemory = "in_memory"

	defaultBypassHeader = "X-Cache-Bypass" // #nosec G101 -- HTTP header name, not a credential
)

type embeddingConfig struct {
	Provider string `mapstructure:"provider"`
	Model    string `mapstructure:"model"`
	APIKey   string `mapstructure:"api_key"` // #nosec G101 -- config field name, not a credential
}

type config struct {
	SimilarityThreshold float64 `mapstructure:"similarity_threshold"`

	TTL        string `mapstructure:"ttl"`
	TTLSeconds int    `mapstructure:"ttl_seconds"`

	Scope       string `mapstructure:"scope"`
	Mode        string `mapstructure:"mode"`
	VectorStore string `mapstructure:"vector_store"`

	EmbeddingProvider string          `mapstructure:"embedding_provider"`
	EmbeddingModel    string          `mapstructure:"embedding_model"`
	Embedding         embeddingConfig `mapstructure:"embedding"`

	CacheOnlyOnStatus  []int  `mapstructure:"cache_only_on_status"`
	BypassHeader       string `mapstructure:"bypass_header"`
	SkipIfToolsPresent *bool  `mapstructure:"skip_if_tools_present"`
	SkipIfStreaming    bool   `mapstructure:"skip_if_streaming"`
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *config) applyDefaults() {
	if c.SimilarityThreshold == 0 {
		c.SimilarityThreshold = defaultSimilarityThreshold
	}
}

func (c *config) validate() error {
	if c.SimilarityThreshold <= 0 || c.SimilarityThreshold > 1 {
		return fmt.Errorf("semantic_cache: similarity_threshold must be in (0, 1], got %f", c.SimilarityThreshold)
	}
	if c.TTL != "" && c.TTLSeconds == 0 {
		if _, err := time.ParseDuration(c.TTL); err != nil {
			return fmt.Errorf("semantic_cache: ttl must be a valid duration: %w", err)
		}
	}
	if c.TTLSeconds < 0 {
		return fmt.Errorf("semantic_cache: ttl_seconds must be non-negative, got %d", c.TTLSeconds)
	}
	if err := validateEnum("mode", c.Mode, modeExact, modeSemantic, modeBoth); err != nil {
		return err
	}
	if err := validateEnum("scope", c.Scope, scopeConsumer, scopeGlobal); err != nil {
		return err
	}
	if err := validateEnum("vector_store", c.VectorStore, storeRedis, storePgvector, storeInMemory); err != nil {
		return err
	}
	return nil
}

func validateEnum(name, value string, allowed ...string) error {
	if value == "" {
		return nil
	}
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("semantic_cache: %s must be one of %v, got %q", name, allowed, value)
}

func (c *config) resolvedTTL() time.Duration {
	if c.TTLSeconds > 0 {
		return time.Duration(c.TTLSeconds) * time.Second
	}
	if c.TTL != "" {
		if d, err := time.ParseDuration(c.TTL); err == nil && d > 0 {
			return d
		}
	}
	return defaultTTLSeconds * time.Second
}

func (c *config) provider() string {
	if c.EmbeddingProvider != "" {
		return c.EmbeddingProvider
	}
	if c.Embedding.Provider != "" {
		return c.Embedding.Provider
	}
	return defaultProvider
}

func (c *config) model() string {
	if c.EmbeddingModel != "" {
		return c.EmbeddingModel
	}
	if c.Embedding.Model != "" {
		return c.Embedding.Model
	}
	return defaultModel
}

func (c *config) mode() string {
	if c.Mode != "" {
		return c.Mode
	}
	return modeSemantic
}

func (c *config) scope() string {
	if c.Scope != "" {
		return c.Scope
	}
	return scopeConsumer
}

func (c *config) vectorStore() string {
	if c.VectorStore != "" {
		return c.VectorStore
	}
	return storeRedis
}

func (c *config) bypassHeader() string {
	if c.BypassHeader != "" {
		return c.BypassHeader
	}
	return defaultBypassHeader
}

func (c *config) skipIfTools() bool {
	if c.SkipIfToolsPresent == nil {
		return true
	}
	return *c.SkipIfToolsPresent
}

func (c *config) cacheableStatus(code int) bool {
	if len(c.CacheOnlyOnStatus) == 0 {
		return code >= 200 && code < 300
	}
	for _, s := range c.CacheOnlyOnStatus {
		if s == code {
			return true
		}
	}
	return false
}

func (c *config) embeddingDomainConfig() *embedding.Config {
	return &embedding.Config{
		Provider:    c.provider(),
		Model:       c.model(),
		Credentials: embedding.Credentials{APIKey: c.Embedding.APIKey},
	}
}
