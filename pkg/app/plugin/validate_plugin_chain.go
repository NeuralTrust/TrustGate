package plugin

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
)

type (
	ValidatePluginChain interface {
		Validate(ctx context.Context, gatewayID uuid.UUID, plugins []types.PluginConfig) error
	}
	validatePluginChain struct {
		manager plugins.Manager
		repo    gateway.Repository
	}
)

func NewValidatePluginChain(manager plugins.Manager, repo gateway.Repository) ValidatePluginChain {
	return &validatePluginChain{
		manager: manager,
		repo:    repo,
	}
}

func (v *validatePluginChain) Validate(ctx context.Context, gatewayID uuid.UUID, plugins []types.PluginConfig) error {
	if len(plugins) == 0 {
		return nil
	}

	pluginMap := make(map[string]types.PluginConfig, len(plugins))
	for _, plugin := range plugins {
		pluginMap[plugin.Name] = plugin
	}

	for _, plugin := range plugins {
		if err := v.manager.ValidatePlugin(plugin.Name, plugin); err != nil {
			return err
		}

		currentPlugin := v.manager.GetPlugin(plugin.Name)
		if currentPlugin == nil {
			return fmt.Errorf("plugin definition not found for %s", plugin.Name)
		}

		for _, required := range currentPlugin.RequiredPlugins() {
			if _, ok := pluginMap[required]; ok {
				continue
			}
			requiredFound := false
			for _, stage := range currentPlugin.Stages() {
				entity, err := v.repo.Get(ctx, gatewayID)
				if err != nil {
					return err
				}
				for _, p := range entity.RequiredPlugins {
					if p.Name == required && p.Stage == stage {
						requiredFound = true
						break
					}
				}
				if requiredFound {
					break
				}
			}
			if !requiredFound {
				return fmt.Errorf("%s %w in stage %s", required, types.ErrRequiredPluginNotFound, plugin.Stage)
			}
		}
	}
	return nil
}
