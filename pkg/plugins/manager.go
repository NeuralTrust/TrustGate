package plugins

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	providersFactory "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/bedrock_guardrail"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/bot_detector"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/code_sanitation"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/contextual_security"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/cors"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/data_masking"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/external_api"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/injection_protection"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/ip_whitelist"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/neuraltrust_jailbreak"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/neuraltrust_moderation"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/neuraltrust_toxicity"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/rate_limiter"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/request_size_limiter"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/token_rate_limiter"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/toxicity_azure"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/toxicity_openai"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	instance Manager
	once     sync.Once
)

//go:generate mockery --name=Manager --dir=. --output=../../mocks --filename=plugin_manager_mock.go --case=underscore --with-expecter
type Manager interface {
	ValidatePlugin(name string, config types.PluginConfig) error
	RegisterPlugin(plugin pluginiface.Plugin) error
	ClearPluginChain(id string)
	GetChains(entityID string, stage types.Stage) [][]types.PluginConfig
	SetPluginChain(gatewayId string, chains []types.PluginConfig) error
	GetPlugin(name string) pluginiface.Plugin
	InitializePlugins()
	ExecuteStage(
		ctx context.Context,
		stage types.Stage,
		gatewayID string,
		req *types.RequestContext,
		resp *types.ResponseContext,
		collector *metrics.Collector,
	) (*types.ResponseContext, error)
	ExecuteChain(
		ctx context.Context,
		chain []types.PluginConfig,
		req *types.RequestContext,
		resp *types.ResponseContext,
		collector *metrics.Collector,
	) (*types.ResponseContext, error)
}

type manager struct {
	mu                 sync.RWMutex
	config             *config.Config
	cache              *cache.Cache
	logger             *logrus.Logger
	bedrockClient      bedrock.Client
	fingerprintTracker fingerprint.Tracker
	embeddingRepo      embedding.EmbeddingRepository
	serviceLocator     factory.EmbeddingServiceLocator
	plugins            map[string]pluginiface.Plugin
	configurations     map[string][][]types.PluginConfig
	providerLocator    providersFactory.ProviderLocator
	firewallClient     firewall.Client
}

func NewManager(
	config *config.Config,
	cache *cache.Cache,
	logger *logrus.Logger,
	bedrockClient bedrock.Client,
	fingerprintTracker fingerprint.Tracker,
	embeddingRepo embedding.EmbeddingRepository,
	serviceLocator factory.EmbeddingServiceLocator,
	providerFactory providersFactory.ProviderLocator,
	firewallClient firewall.Client,
) Manager {
	once.Do(func() {
		instance = &manager{
			plugins:            make(map[string]pluginiface.Plugin),
			configurations:     make(map[string][][]types.PluginConfig),
			bedrockClient:      bedrockClient,
			cache:              cache,
			logger:             logger,
			config:             config,
			fingerprintTracker: fingerprintTracker,
			embeddingRepo:      embeddingRepo,
			serviceLocator:     serviceLocator,
			providerLocator:    providerFactory,
			firewallClient:     firewallClient,
		}
		instance.InitializePlugins()
	})
	return instance
}

func (m *manager) InitializePlugins() {

	if err := m.RegisterPlugin(rate_limiter.NewRateLimiterPlugin(m.cache.Client(), nil)); err != nil {
		m.logger.WithError(err).Error("Failed to register rate limiter plugin")
	}

	if err := m.RegisterPlugin(ip_whitelist.NewIPWhitelistPlugin(m.logger)); err != nil {
		m.logger.WithError(err).Error("Failed to register ip whitelist plugin")
	}

	if err := m.RegisterPlugin(external_api.NewExternalApiPlugin(&http.Client{})); err != nil {
		m.logger.WithError(err).Error("Failed to register external API plugin")
	}

	if err := m.RegisterPlugin(token_rate_limiter.NewTokenRateLimiterPlugin(m.logger, m.cache.Client())); err != nil {
		m.logger.WithError(err).Error("Failed to register token rate limiter plugin")
	}

	if err := m.RegisterPlugin(data_masking.NewDataMaskingPlugin(m.logger, m.cache)); err != nil {
		m.logger.WithError(err).Error("Failed to register data masking plugin")
	}

	if err := m.RegisterPlugin(toxicity_openai.NewToxicityOpenAIPlugin(m.logger, &http.Client{})); err != nil {
		m.logger.WithError(err).Error("Failed to register toxicity openai plugin")
	}

	if err := m.RegisterPlugin(toxicity_azure.NewToxicityAzurePlugin(m.logger, &http.Client{})); err != nil {
		m.logger.WithError(err).Error("Failed to register toxicity azure plugin")
	}

	if err := m.RegisterPlugin(bedrock_guardrail.NewBedrockGuardrailPlugin(m.logger, m.bedrockClient)); err != nil {
		m.logger.WithError(err).Error("Failed to register bedrock guardrail plugin")
	}

	if err := m.RegisterPlugin(request_size_limiter.NewRequestSizeLimiterPlugin(m.logger)); err != nil {
		m.logger.WithError(err).Error("Failed to register request size limiter plugin")
	}

	if err := m.RegisterPlugin(injection_protection.NewInjectionProtectionPlugin(m.logger)); err != nil {
		m.logger.WithError(err).Error("Failed to register injection protection plugin")
	}

	if err := m.RegisterPlugin(code_sanitation.NewCodeSanitationPlugin(m.logger)); err != nil {
		m.logger.WithError(err).Error("Failed to register code sanitation plugin")
	}

	if err := m.RegisterPlugin(neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		m.logger,
		m.firewallClient,
		m.fingerprintTracker,
	)); err != nil {
		m.logger.WithError(err).Error("Failed to register trustgate guardrail plugin")
	}

	if err := m.RegisterPlugin(contextual_security.NewContextualSecurityPlugin(
		m.fingerprintTracker,
		m.logger,
	)); err != nil {
		m.logger.WithError(err).Error("Failed to register trustgate guardrail plugin")
	}

	if err := m.RegisterPlugin(cors.NewCorsPlugin(
		m.logger,
	)); err != nil {
		m.logger.WithError(err).Error("Failed to register trustgate guardrail plugin")
	}

	if err := m.RegisterPlugin(neuraltrust_toxicity.NewNeuralTrustToxicity(
		m.logger,
		m.fingerprintTracker,
		m.firewallClient,
	)); err != nil {
		m.logger.WithError(err).Error("Failed to register toxicity neuraltrust plugin")
	}

	if err := m.RegisterPlugin(neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		m.logger,
		&http.Client{ //nolint
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
			},
		},
		m.fingerprintTracker,
		m.embeddingRepo,
		m.serviceLocator,
		m.providerLocator,
	)); err != nil {
		m.logger.WithError(err).Error("Failed to register toxicity neuraltrust plugin")
	}

	if err := m.RegisterPlugin(bot_detector.NewBotDetectorPlugin(
		m.logger,
		m.fingerprintTracker,
	)); err != nil {
		m.logger.WithError(err).Error("Failed to register bot detector plugin")
	}

}

// ValidatePlugin validates a plugin configuration
func (m *manager) ValidatePlugin(name string, config types.PluginConfig) error {
	plugin, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("unknown plugin: %s", name)
	}

	if err := plugin.ValidateConfig(config); err != nil {
		m.logger.WithError(err).Errorf("Plugin %s validation failed", name)
		return err
	}

	return nil
}

func (m *manager) RegisterPlugin(plugin pluginiface.Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := plugin.Name()
	if _, exists := m.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}
	m.plugins[name] = plugin
	return nil
}

func (m *manager) ClearPluginChain(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.configurations[id]; !exists {
		return
	}

	delete(m.configurations, id)
}

func (m *manager) SetPluginChain(gatewayId string, chains []types.PluginConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, chain := range chains {
		if _, exists := m.plugins[chain.Name]; !exists {
			return fmt.Errorf("plugin %s not registered", chain.Name)
		}
	}

	if m.configurations[gatewayId] == nil {
		m.configurations[gatewayId] = [][]types.PluginConfig{}
	}

	m.configurations[gatewayId] = append(m.configurations[gatewayId], chains)

	return nil
}

func (m *manager) ExecuteStage(
	ctx context.Context,
	stage types.Stage,
	gatewayID string,
	req *types.RequestContext,
	resp *types.ResponseContext,
	collector *metrics.Collector,
) (*types.ResponseContext, error) {
	m.mu.RLock()
	// Get both gateway and rule level chains
	gatewayChains := m.GetChains(gatewayID, stage)
	plugins := m.plugins
	m.mu.RUnlock()

	// Set the current stage in the request context
	req.Stage = stage

	// Track executed plugins to prevent duplicates
	executedPlugins := make(map[string]bool)

	// Chains are inserted in PluginChain Middleware and in Forwarded Handler
	for _, chain := range gatewayChains {
		if len(chain) > 0 {
			if err := m.executeChains(ctx, plugins, chain, req, resp, executedPlugins, collector); err != nil {
				return resp, err
			}
		}
	}

	return resp, nil
}

func (m *manager) ExecuteChain(
	ctx context.Context,
	chain []types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	collector *metrics.Collector,
) (*types.ResponseContext, error) {
	if len(chain) > 0 {
		executedPlugins := make(map[string]bool)
		if err := m.executeChains(ctx, m.plugins, chain, req, resp, executedPlugins, collector); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

func (m *manager) executeChains(
	ctx context.Context,
	plugins map[string]pluginiface.Plugin,
	chains []types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	executedPlugins map[string]bool,
	collector *metrics.Collector,
) error {
	// Group parallel and sequential chains
	var parallelChains, sequentialChains []types.PluginConfig
	for _, chain := range chains {
		// Create a unique identifier using plugin ID
		pluginInstanceID := chain.ID
		if pluginInstanceID == "" {
			// Fallback to name if ID is not set
			pluginInstanceID = chain.Name
		}

		// Skip if this specific plugin instance was already executed in this stage
		if executedPlugins[pluginInstanceID] {
			continue
		}
		executedPlugins[pluginInstanceID] = true

		if chain.Parallel {
			parallelChains = append(parallelChains, chain)
		} else {
			sequentialChains = append(sequentialChains, chain)
		}
	}

	// Execute parallel chains first
	if len(parallelChains) > 0 {
		if err := m.executeParallel(ctx, plugins, parallelChains, req, resp, collector); err != nil {
			return err
		}
	}

	// Then execute sequential chains
	if len(sequentialChains) > 0 {
		if err := m.executeSequential(ctx, plugins, sequentialChains, req, resp, collector); err != nil {
			return err
		}
	}

	return nil
}

func (m *manager) executeSequential(
	ctx context.Context,
	plugins map[string]pluginiface.Plugin,
	configs []types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	metricsCollector *metrics.Collector,
) error {
	sortedConfigs := make([]types.PluginConfig, len(configs))
	copy(sortedConfigs, configs)
	sort.Slice(sortedConfigs, func(i, j int) bool {
		return sortedConfigs[i].Priority < sortedConfigs[j].Priority
	})

	for _, cfg := range sortedConfigs {
		if !cfg.Enabled {
			continue
		}

		if plugin, exists := plugins[cfg.Name]; exists {
			wrappedPlugin := NewPluginWrapper(plugin, metricsCollector)
			pluginResp, err := wrappedPlugin.Execute(ctx, cfg, req, resp)
			if err != nil {
				return err
			}
			if pluginResp != nil {
				m.mu.Lock()
				resp.StatusCode = pluginResp.StatusCode
				if pluginResp.Body != nil {
					resp.Body = pluginResp.Body
				}
				if resp.Headers == nil {
					resp.Headers = map[string][]string{}
				}
				if pluginResp.Headers != nil {
					for k, v := range pluginResp.Headers {
						resp.Headers[k] = v
					}
				}
				if pluginResp.Metadata != nil {
					for k, v := range pluginResp.Metadata {
						resp.Metadata[k] = v
					}
				}
				m.mu.Unlock()
			}
		}
	}
	return nil
}

func (m *manager) executeParallel(
	ctx context.Context,
	plugins map[string]pluginiface.Plugin,
	configs []types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	metricsCollector *metrics.Collector,
) error {

	priorityGroups := make(map[int][]types.PluginConfig)
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		priorityGroups[cfg.Priority] = append(priorityGroups[cfg.Priority], cfg)
	}
	priorities := make([]int, 0, len(priorityGroups))
	for p := range priorityGroups {
		priorities = append(priorities, p)
	}
	sort.Ints(priorities)

	for _, priority := range priorities {
		group := priorityGroups[priority]

		type pluginResult struct {
			cfg       types.PluginConfig
			resp      *types.PluginResponse
			startTime time.Time
			endTime   time.Time
		}

		results := make([]pluginResult, 0, len(group))
		var resultsMu sync.Mutex

		g, gctx := errgroup.WithContext(ctx)

		for i := range group {
			cfg := group[i]
			g.Go(func() error {
				evt := metric_events.NewPluginEvent()
				evt.Plugin = &metric_events.PluginDataEvent{
					PluginName: cfg.Name,
					Stage:      string(req.Stage),
				}

				plugin, ok := plugins[cfg.Name]
				if !ok {
					pe := &types.PluginError{
						Err:        errors.New("plugin not found: " + cfg.Name),
						StatusCode: 500,
					}
					m.applyPluginErrorToResponse(pe, resp)
					return pe
				}

				wrapped := NewPluginWrapper(plugin, metricsCollector)
				start := time.Now()
				pluginResp, err := wrapped.Execute(gctx, cfg, req, resp)
				end := time.Now()

				select {
				case <-gctx.Done():
					// We don't return nil: we need to propagate the canceled context so the group finishes,
					// but we also don't want to overwrite the first error with a late context.Canceled.
					// We return gctx.Err() to exit quickly.
					return gctx.Err()
				default:
				}

				if err != nil {
					// First error: set StatusCode + Headers in resp and automatically cancel the rest (errgroup)
					// If it's a *types.PluginError, extract metadata
					var pe *types.PluginError
					if errors.As(err, &pe) {
						m.applyPluginErrorToResponse(pe, resp)
						return pe
					}
					pe = &types.PluginError{
						Err:        err,
						StatusCode: 500,
					}
					m.applyPluginErrorToResponse(pe, resp)
					return pe
				}

				// Success: store the result to apply later (only if there were NO errors in the group)
				if pluginResp != nil {
					resultsMu.Lock()
					results = append(results, pluginResult{
						cfg:       cfg,
						resp:      pluginResp,
						startTime: start,
						endTime:   end,
					})
					resultsMu.Unlock()
				}
				return nil
			})
		}

		// Group wait: if it returns an error, it was the first one and we've already set resp (headers/status)
		if err := g.Wait(); err != nil {
			return err
		}

		// If there were no errors, apply all successful results
		// Deterministic order by plugin name (or any field from cfg you prefer)
		sort.Slice(results, func(i, j int) bool {
			return results[i].cfg.Name < results[j].cfg.Name
		})

		for _, r := range results {
			if r.resp == nil {
				continue
			}
			m.mu.Lock()
			if r.resp.StatusCode > 0 {
				resp.StatusCode = r.resp.StatusCode
			}
			if r.resp.Body != nil {
				resp.Body = r.resp.Body
			}
			if r.resp.Headers != nil {
				if resp.Headers == nil {
					resp.Headers = make(map[string][]string, len(r.resp.Headers))
				}
				for k, v := range r.resp.Headers {
					resp.Headers[k] = v
				}
			}
			if r.resp.Metadata != nil {
				if resp.Metadata == nil {
					resp.Metadata = make(map[string]interface{}, len(r.resp.Metadata))
				}
				for k, v := range r.resp.Metadata {
					resp.Metadata[k] = v
				}
			}
			m.mu.Unlock()
		}
	}

	return nil
}

func (m *manager) applyPluginErrorToResponse(pe *types.PluginError, resp *types.ResponseContext) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pe.StatusCode > 0 {
		resp.StatusCode = pe.StatusCode
	} else {
		resp.StatusCode = 500
	}
	if pe.Headers != nil {
		if resp.Headers == nil {
			resp.Headers = make(map[string][]string, len(pe.Headers))
		}
		for k, v := range pe.Headers {
			resp.Headers[k] = v
		}
	}
	if pe.Metadata != nil {
		if resp.Metadata == nil {
			resp.Metadata = make(map[string]interface{}, len(pe.Metadata))
		}
		for k, v := range pe.Metadata {
			resp.Metadata[k] = v
		}
	}
}

func (m *manager) GetChains(entityID string, stage types.Stage) [][]types.PluginConfig {

	chainsGroups, exists := m.configurations[entityID]

	if !exists {
		return nil
	}
	var stageChains [][]types.PluginConfig
	for _, chains := range chainsGroups {
		var filteredGroup []types.PluginConfig
		for _, chain := range chains {
			plugin, exists := m.plugins[chain.Name]
			if !exists {
				continue
			}
			fixedStages := plugin.Stages()
			if len(fixedStages) > 0 {
				for _, fixedStage := range fixedStages {
					if fixedStage == stage {
						chainConfig := chain
						chainConfig.Stage = stage
						filteredGroup = append(filteredGroup, chainConfig)
						break
					}
				}
				continue
			}
			allowedStages := plugin.AllowedStages()
			if chain.Stage == "" {
				continue
			}
			if chain.Stage == stage {
				for _, allowedStage := range allowedStages {
					if allowedStage == stage {
						filteredGroup = append(filteredGroup, chain)
						break
					}
				}
			}
		}
		if len(filteredGroup) > 0 {
			stageChains = append(stageChains, filteredGroup)
		}
	}
	return stageChains
}

// GetPlugin returns a plugin by name
func (m *manager) GetPlugin(name string) pluginiface.Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.plugins[name]
}
