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
	defaultTTL                 = "24h"
	defaultProvider            = "openai"
	defaultModel               = "text-embedding-ada-002"
)

type embeddingConfig struct {
	Provider string `mapstructure:"provider"`
	Model    string `mapstructure:"model"`
	APIKey   string `mapstructure:"api_key"` // #nosec G101 -- config field name, not a credential
}

type config struct {
	SimilarityThreshold float64         `mapstructure:"similarity_threshold"`
	TTL                 string          `mapstructure:"ttl"`
	Embedding           embeddingConfig `mapstructure:"embedding"`
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
	if c.TTL == "" {
		c.TTL = defaultTTL
	}
	if c.Embedding.Provider == "" {
		c.Embedding.Provider = defaultProvider
	}
	if c.Embedding.Model == "" {
		c.Embedding.Model = defaultModel
	}
}

func (c *config) validate() error {
	if c.SimilarityThreshold <= 0 || c.SimilarityThreshold > 1 {
		return fmt.Errorf("semantic_cache: similarity_threshold must be in (0, 1], got %f", c.SimilarityThreshold)
	}
	ttl, err := time.ParseDuration(c.TTL)
	if err != nil {
		return fmt.Errorf("semantic_cache: ttl must be a valid duration: %w", err)
	}
	if ttl <= 0 {
		return fmt.Errorf("semantic_cache: ttl must be positive, got %s", c.TTL)
	}
	if c.Embedding.APIKey == "" {
		return fmt.Errorf("semantic_cache: embedding.api_key is required")
	}
	return nil
}

func (c *config) parsedTTL() time.Duration {
	ttl, err := time.ParseDuration(c.TTL)
	if err != nil {
		return 24 * time.Hour
	}
	return ttl
}

func (c *config) embeddingDomainConfig() *embedding.Config {
	return &embedding.Config{
		Provider:    c.Embedding.Provider,
		Model:       c.Embedding.Model,
		Credentials: embedding.Credentials{APIKey: c.Embedding.APIKey},
	}
}
