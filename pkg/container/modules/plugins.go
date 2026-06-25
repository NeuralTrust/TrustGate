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

package modules

import (
	"log/slog"
	"os"

	cataloghttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/catalog"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/semantic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	embeddingfactory "github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/azurecontentsafety"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/bedrockguardrail"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/cors"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/costcap"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/modelallowlist"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/openaimoderation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pertoolratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/prompttemplate"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/requestsize"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/semanticcache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/tokenratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/tool_call_validation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/toolallowlist"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/tooltransform"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/trustguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/dig"
)

const vectorStoreEnv = "SEMANTIC_CACHE_VECTOR_STORE"

type pluginParams struct {
	dig.In
	Cache    cache.Client
	Adapters *adapter.Registry
	Locator  embeddingfactory.EmbeddingServiceLocator
	Logger   *slog.Logger
	Pricing  appcatalog.PricingResolver
	Cfg      *config.Config
	DB       *database.Connection `optional:"true"`
}

func Plugins(c *container.Container) error {
	if err := c.Provide(newPluginRegistry); err != nil {
		return err
	}
	if err := c.Provide(func(reg appplugins.Registry, logger *slog.Logger) appplugins.Executor {
		return appplugins.NewExecutor(reg, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(appplugins.NewCatalogService); err != nil {
		return err
	}
	return c.Provide(cataloghttp.NewListPolicyCatalogHandler)
}

// newPluginRegistry builds the plugin catalog and registers every built-in
// plugin with its infrastructure dependencies.
func newPluginRegistry(p pluginParams) (appplugins.Registry, error) {
	reg := appplugins.NewRegistry()
	redisClient := p.Cache.RedisClient()
	store, err := semantic.NewStore(vectorStoreKind(), semantic.Deps{
		Redis:  redisClient,
		Pool:   poolOrNil(p.DB),
		Logger: p.Logger,
	})
	if err != nil {
		return nil, err
	}

	catalog := []appplugins.Plugin{
		ratelimit.New(redisClient),
		tokenratelimit.New(redisClient, p.Adapters, p.Pricing),
		costcap.New(p.Pricing),
		pertoolratelimit.New(redisClient, p.Adapters),
		requestsize.New(),
		cors.New(),
		semanticcache.New(store, p.Locator, p.Adapters),
		modelallowlist.New(),
		prompttemplate.New(),
		toolallowlist.New(p.Adapters),
		tool_call_validation.New(p.Adapters, openai.NewOpenaiClient(), p.Logger),
		tooltransform.New(p.Adapters),
		trustguard.New(p.Adapters, p.Cfg.TrustGuard.BaseURL, p.Cfg.TrustGuard.Timeout, p.Logger),
		openaimoderation.New(p.Adapters, p.Cfg.OpenAIModeration.BaseURL, p.Cfg.OpenAIModeration.Timeout, p.Logger),
		azurecontentsafety.New(p.Adapters, p.Logger),
		bedrockguardrail.New(p.Adapters, p.Logger),
	}
	for _, plugin := range catalog {
		if err := reg.Register(plugin); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

func vectorStoreKind() string {
	if kind := os.Getenv(vectorStoreEnv); kind != "" {
		return kind
	}
	return "redis"
}

func poolOrNil(db *database.Connection) *pgxpool.Pool {
	if db == nil {
		return nil
	}
	return db.Pool
}
