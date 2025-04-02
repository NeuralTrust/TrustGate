package plugin

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type (
	ValidatePluginChain interface {
		Validate([]types.PluginConfig) error
	}
	validatePluginChain struct {
		manager *plugins.Manager
	}
)

func NewValidatePluginChain(manager *plugins.Manager) ValidatePluginChain {
	return &validatePluginChain{
		manager: manager,
	}
}

func (v *validatePluginChain) Validate(plugins []types.PluginConfig) error {
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
		for _, required := range currentPlugin.RequiredPlugins() {
			if _, ok := pluginMap[required]; !ok {
				return fmt.Errorf("%s %w", required, types.ErrRequiredPluginNotFound)
			}
		}
	}
	return nil
}
