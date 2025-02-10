package plugins

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/data_masking"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/external_api"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/prompt_moderation"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/rate_limiter"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/token_rate_limiter"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/toxicity_azure"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/toxicity_openai"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

var (
	instance *Manager
	once     sync.Once
)

type Manager struct {
	mu             sync.RWMutex
	cache          *cache.Cache
	logger         *logrus.Logger
	plugins        map[string]pluginiface.Plugin
	configurations map[types.Level]map[string][]types.PluginConfig
}

func GetManager() *Manager {
	once.Do(func() {
		instance = &Manager{
			plugins:        make(map[string]pluginiface.Plugin),
			configurations: make(map[types.Level]map[string][]types.PluginConfig),
		}
	})
	return instance
}

func InitManager(cache *cache.Cache, logger *logrus.Logger) {
	manager := GetManager()
	manager.cache = cache
	manager.logger = logger
}

func InitializePlugins(cache *cache.Cache, logger *logrus.Logger) {
	InitManager(cache, logger)
	manager := GetManager()

	// Register built-in plugins with error handling
	if err := manager.RegisterPlugin(rate_limiter.NewRateLimiterPlugin(cache.Client())); err != nil {
		logger.WithError(err).Error("Failed to register rate limiter plugin")
	}

	if err := manager.RegisterPlugin(external_api.NewExternalApiPlugin()); err != nil {
		logger.WithError(err).Error("Failed to register external API plugin")
	}

	if err := manager.RegisterPlugin(token_rate_limiter.NewTokenRateLimiterPlugin(logger, cache.Client())); err != nil {
		logger.WithError(err).Error("Failed to register token rate limiter plugin")
	}

	if err := manager.RegisterPlugin(prompt_moderation.NewPromptModerationPlugin(logger)); err != nil {
		logger.WithError(err).Error("Failed to register prompt moderation plugin")
	}

	if err := manager.RegisterPlugin(data_masking.NewDataMaskingPlugin(logger)); err != nil {
		logger.WithError(err).Error("Failed to register data masking plugin")
	}

	if err := manager.RegisterPlugin(toxicity_openai.NewToxicityOpenAIPlugin(logger)); err != nil {
		logger.WithError(err).Error("Failed to register toxicity openai plugin")
	}

	if err := manager.RegisterPlugin(toxicity_azure.NewToxicityAzurePlugin(logger)); err != nil {
		logger.WithError(err).Error("Failed to register toxicity azure plugin")
	}
}

// ValidatePlugin validates a plugin configuration
func (m *Manager) ValidatePlugin(name string, config types.PluginConfig) error {
	plugin, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("unknown plugin: %s", name)
	}

	validator, ok := plugin.(pluginiface.PluginValidator)
	if !ok {
		m.logger.Warnf("Plugin %s does not implement PluginValidator interface", name)
		return nil
	}

	if err := validator.ValidateConfig(config); err != nil {
		m.logger.WithError(err).Errorf("Plugin %s validation failed", name)
		return err
	}

	return nil
}

func (m *Manager) RegisterPlugin(plugin pluginiface.Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := plugin.Name()
	if _, exists := m.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	// Ensure the plugin implements the validator interface if it needs validation
	if _, ok := plugin.(pluginiface.PluginValidator); !ok {
		m.logger.Warnf("Plugin %s does not implement PluginValidator interface", name)
	}

	m.plugins[name] = plugin
	return nil
}

func (m *Manager) SetPluginChain(level types.Level, entityID string, chains []types.PluginConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate all plugins exist
	for _, chain := range chains {
		if _, exists := m.plugins[chain.Name]; !exists {
			return fmt.Errorf("plugin %s not registered", chain.Name)
		}
	}

	if m.configurations[level] == nil {
		m.configurations[level] = make(map[string][]types.PluginConfig)
	}

	m.configurations[level][entityID] = chains
	return nil
}

func (m *Manager) ExecuteStage(ctx context.Context, stage types.Stage, gatewayID, ruleID string, req *types.RequestContext, resp *types.ResponseContext) (*types.ResponseContext, error) {
	m.mu.RLock()
	// Get both gateway and rule level chains
	gatewayChains := m.getChains(types.GatewayLevel, gatewayID, stage)
	ruleChains := m.getChains(types.RuleLevel, ruleID, stage)
	plugins := m.plugins
	m.mu.RUnlock()

	// Set the current stage in the request context
	req.Stage = stage

	// Track executed plugins to prevent duplicates
	executedPlugins := make(map[string]bool)

	// Execute gateway-level chains first
	if len(gatewayChains) > 0 {
		if err := m.executeChains(ctx, plugins, gatewayChains, req, resp, executedPlugins); err != nil {
			return resp, err
		}
	}

	// Then execute rule-level chains
	if len(ruleChains) > 0 {
		if err := m.executeChains(ctx, plugins, ruleChains, req, resp, executedPlugins); err != nil {
			return resp, err
		}
	}

	return resp, nil
}

func (m *Manager) executeChains(ctx context.Context, plugins map[string]pluginiface.Plugin, chains []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext, executedPlugins map[string]bool) error {
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
		if err := m.executeParallel(ctx, plugins, parallelChains, req, resp); err != nil {
			return err
		}
	}

	// Then execute sequential chains
	if len(sequentialChains) > 0 {
		if err := m.executeSequential(ctx, plugins, sequentialChains, req, resp); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) executeParallel(ctx context.Context, plugins map[string]pluginiface.Plugin, configs []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) error {
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
			config    types.PluginConfig
			response  *types.PluginResponse
			err       error
			startTime time.Time
			endTime   time.Time
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
					pluginResp, err := plugin.Execute(ctx, cfg, req, resp)

					pluginEndTime := time.Now()
					resultChan <- pluginResult{
						config:    cfg,
						response:  pluginResp,
						err:       err,
						startTime: pluginStartTime,
						endTime:   pluginEndTime,
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

func (m *Manager) executeSequential(ctx context.Context, plugins map[string]pluginiface.Plugin, configs []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) error {
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
			pluginResp, err := plugin.Execute(ctx, cfg, req, resp)
			if err != nil {
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

func (m *Manager) getChains(level types.Level, entityID string, stage types.Stage) []types.PluginConfig {
	if configs, exists := m.configurations[level]; exists {
		if chains, exists := configs[entityID]; exists {
			var stageChains []types.PluginConfig
			for _, chain := range chains {
				// Get the plugin to check its stages
				plugin, exists := m.plugins[chain.Name]
				if !exists {
					continue
				}

				// Check if plugin has fixed stages
				fixedStages := plugin.Stages()
				if len(fixedStages) > 0 {
					// For plugins with fixed stages, check if the current stage is one of them
					for _, fixedStage := range fixedStages {
						if fixedStage == stage {
							chainConfig := chain
							chainConfig.Stage = stage
							stageChains = append(stageChains, chainConfig)
							break
						}
					}
				} else {
					// For plugins without fixed stages, validate against allowed stages
					allowedStages := plugin.AllowedStages()
					// If no stage is configured, skip this plugin
					if chain.Stage == "" {
						continue
					}
					// Check if the configured stage is allowed and matches current stage
					if chain.Stage == stage {
						isAllowed := false
						for _, allowedStage := range allowedStages {
							if allowedStage == stage {
								isAllowed = true
								break
							}
						}
						if isAllowed {
							stageChains = append(stageChains, chain)
						}
					}
				}
			}
			return stageChains
		}
	}
	return nil
}

// GetPlugin returns a plugin by name
func (m *Manager) GetPlugin(name string) pluginiface.Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.plugins[name]
}
