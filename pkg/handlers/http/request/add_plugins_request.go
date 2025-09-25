package request

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type AddPluginsRequest struct {
	Type    string               `json:"type"`
	ID      string               `json:"id"`
	Plugins []types.PluginConfig `json:"plugins"`
}

func (r *AddPluginsRequest) Validate() error {
	if r.Type != "gateway" && r.Type != "rule" {
		return fmt.Errorf("type must be 'gateway' or 'rule'")
	}
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if len(r.Plugins) == 0 {
		return fmt.Errorf("plugins is required")
	}
	for i, p := range r.Plugins {
		if p.Name == "" {
			return fmt.Errorf("plugin name at index %d is required", i)
		}
		if p.Stage == "" {
			return fmt.Errorf("plugin stage at index %d is required", i)
		}
	}
	return nil
}
