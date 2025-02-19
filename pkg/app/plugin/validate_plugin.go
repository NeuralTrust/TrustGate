package plugin

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type ValidatePlugin struct {
}

func NewValidatePlugin() *ValidatePlugin {
	return &ValidatePlugin{}
}

func (s *ValidatePlugin) Validate(plugin types.PluginConfig) error {
	// Validate required fields
	if plugin.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	if plugin.Stage == "" {
		return fmt.Errorf("plugin stage is required")
	}

	// Validate settings
	if plugin.Settings == nil {
		return fmt.Errorf("plugin settings are required")
	}

	// Validate stage
	validStages := map[types.Stage]bool{
		types.PreRequest:   true,
		types.PostRequest:  true,
		types.PreResponse:  true,
		types.PostResponse: true,
	}
	if !validStages[plugin.Stage] {
		return fmt.Errorf("invalid plugin stage: %s", plugin.Stage)
	}

	// Validate priority (0-999)
	if plugin.Priority < 0 || plugin.Priority > 999 {
		return fmt.Errorf("plugin priority must be between 0 and 999")
	}

	// Get plugin validator
	manager := plugins.GetManager()
	if err := manager.ValidatePlugin(plugin.Name, plugin); err != nil {
		return fmt.Errorf("unknown plugin: %s", plugin.Name)
	}
	return nil
}
