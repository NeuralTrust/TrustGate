package plugins

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/contextual_security"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/cors"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/neuraltrust_guardrail"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/bedrock_guardrail"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/code_sanitation"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/data_masking"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/external_api"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/injection_protection"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/prompt_moderation"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/rate_limiter"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/request_size_limiter"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/token_rate_limiter"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/toxicity_azure"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/toxicity_openai"
	"github.com/NeuralTrust/TrustGate/pkg/types"
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
}

func NewManager(
	config *config.Config,
	cache *cache.Cache,
	logger *logrus.Logger,
	bedrockClient bedrock.Client,
	fingerprintTracker fingerprint.Tracker,
	embeddingRepo embedding.EmbeddingRepository,
	serviceLocator factory.EmbeddingServiceLocator,
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
		}
	})
	instance.InitializePlugins()
	return instance
}

func (m *manager) InitializePlugins() {

	if err := m.RegisterPlugin(rate_limiter.NewRateLimiterPlugin(m.cache.Client(), nil)); err != nil {
		m.logger.WithError(err).Error("Failed to register rate limiter plugin")
	}

	if err := m.RegisterPlugin(external_api.NewExternalApiPlugin(&http.Client{})); err != nil {
		m.logger.WithError(err).Error("Failed to register external API plugin")
	}

	if err := m.RegisterPlugin(token_rate_limiter.NewTokenRateLimiterPlugin(m.logger, m.cache.Client())); err != nil {
		m.logger.WithError(err).Error("Failed to register token rate limiter plugin")
	}

	if err := m.RegisterPlugin(prompt_moderation.NewPromptModerationPlugin(m.logger)); err != nil {
		m.logger.WithError(err).Error("Failed to register prompt moderation plugin")
	}

	if err := m.RegisterPlugin(data_masking.NewDataMaskingPlugin(m.logger)); err != nil {
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

	if err := m.RegisterPlugin(neuraltrust_guardrail.NewNeuralTrustGuardrailPlugin(
		m.logger,
		&http.Client{},
		m.fingerprintTracker,
		m.embeddingRepo,
		m.serviceLocator,
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

func (m *manager) executeParallel(
	ctx context.Context,
	plugins map[string]pluginiface.Plugin,
	configs []types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	metricsCollector *metrics.Collector,
) error {
	// Group plugins by priority
	priorityGroups := make(map[int][]types.PluginConfig)
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		priorityGroups[cfg.Priority] = append(priorityGroups[cfg.Priority], cfg)
	}

	// Get sorted priorities
	priorities := make([]int, 0, len(priorityGroups))
	for p := range priorityGroups {
		priorities = append(priorities, p)
	}
	sort.Ints(priorities)

	// Execute plugins by priority groups
	for _, priority := range priorities {
		group := priorityGroups[priority]

		// Create channels for results and errors
		type pluginResult struct {
			pluginName string
			config     types.PluginConfig
			response   *types.PluginResponse
			err        error
			startTime  time.Time
			endTime    time.Time
		}
		resultChan := make(chan pluginResult, len(group))

		// Launch all plugins in the group simultaneously
		var wg sync.WaitGroup
		for i := range group {
			cfg := group[i]
			wg.Add(1)
			go func(cfg types.PluginConfig) {
				defer wg.Done()

				pluginStartTime := time.Now()
				if plugin, exists := plugins[cfg.Name]; exists {
					pluginResp, err := plugin.Execute(ctx, cfg, req, resp, metricsCollector)
					pluginEndTime := time.Now()
					resultChan <- pluginResult{
						pluginName: cfg.Name,
						config:     cfg,
						response:   pluginResp,
						err:        err,
						startTime:  pluginStartTime,
						endTime:    pluginEndTime,
					}
				}
			}(cfg)
		}

		// Start a goroutine to close resultChan when all plugins finish
		go func() {
			wg.Wait()
			close(resultChan)
		}()

		// Collect results
		var results []pluginResult
		var errors []error

		// Wait for all results or context cancellation
		for result := range resultChan {
			if result.err != nil {
				m.raisePluginErrorEvent(metricsCollector, result.pluginName, string(req.Stage), result.err)
				errors = append(errors, result.err)
			}
			if result.response != nil {
				results = append(results, result)
			}

			select {
			case <-ctx.Done():
				m.logger.Errorf("Context cancelled while processing results: %v", ctx.Err())
				return ctx.Err()
			default:
			}
		}

		// Sort results by plugin priority
		sort.Slice(results, func(i, j int) bool {
			return results[i].config.Priority < results[j].config.Priority
		})

		// Apply all successful responses
		for _, result := range results {
			if result.response != nil {
				m.mu.Lock()
				resp.StatusCode = result.response.StatusCode
				resp.Body = result.response.Body
				if result.response.Headers != nil {
					for k, v := range result.response.Headers {
						resp.Headers[k] = v
					}
				}
				if result.response.Metadata != nil {
					for k, v := range result.response.Metadata {
						resp.Metadata[k] = v
					}
				}
				m.mu.Unlock()
			}
		}

		// If any plugin returned an error, return the first one
		if len(errors) > 0 {
			return errors[0]
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
			pluginResp, err := plugin.Execute(ctx, cfg, req, resp, metricsCollector)
			if err != nil {
				m.raisePluginErrorEvent(metricsCollector, cfg.Name, string(req.Stage), err)
				return err
			}
			if pluginResp != nil {
				m.mu.Lock()
				resp.StatusCode = pluginResp.StatusCode
				if pluginResp.Body != nil {
					resp.Body = pluginResp.Body
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

func (m *manager) raisePluginErrorEvent(metricsCollector *metrics.Collector, pluginName, stage string, err error) {
	evt := metric_events.NewPluginEvent()
	evt.Plugin = &metric_events.PluginDataEvent{
		PluginName:   pluginName,
		Stage:        stage,
		Error:        true,
		ErrorMessage: err.Error(),
	}
	metricsCollector.Emit(evt)
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
