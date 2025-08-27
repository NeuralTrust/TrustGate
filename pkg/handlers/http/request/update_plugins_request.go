package request

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type PluginOperation string

const (
	PluginOperationAdd    PluginOperation = "add"
	PluginOperationEdit   PluginOperation = "edit"
	PluginOperationDelete PluginOperation = "delete"
)

type PluginUpdate struct {
	Operation PluginOperation    `json:"operation"`
	Plugin    types.PluginConfig `json:"plugin,omitempty"`
	// For delete operation, we only need the plugin name
	PluginName string `json:"plugin_name,omitempty"`
	// For edit operation, we can optionally specify which plugin to update by name
	// if the name itself is being changed
	OldPluginName string `json:"old_plugin_name,omitempty"`
}

type UpdatePluginsRequest struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	// Granular updates for add/edit/delete operations
	Updates []PluginUpdate `json:"updates"`
}

func (r *UpdatePluginsRequest) Validate() error {
	if r.Type != "gateway" && r.Type != "rule" {
		return fmt.Errorf("type must be 'gateway' or 'rule'")
	}
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}

	// Updates are required
	if len(r.Updates) == 0 {
		return fmt.Errorf("at least one update operation is required")
	}

	// Validate individual updates
	for i, update := range r.Updates {
		if err := validatePluginUpdate(update); err != nil {
			return fmt.Errorf("invalid update at index %d: %w", i, err)
		}
	}

	return nil
}

func validatePluginUpdate(update PluginUpdate) error {
	switch update.Operation {
	case PluginOperationAdd, PluginOperationEdit:
		if update.Plugin.Name == "" {
			return fmt.Errorf("plugin name is required for %s operation", update.Operation)
		}
	case PluginOperationDelete:
		if update.PluginName == "" && update.Plugin.Name == "" {
			return fmt.Errorf("plugin name is required for delete operation")
		}
	default:
		return fmt.Errorf("invalid operation: %s", update.Operation)
	}
	return nil
}
