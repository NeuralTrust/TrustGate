package request

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type UpdatePluginsRequest struct {
	Type        string               `json:"type"`
	ID          string               `json:"id"`
	PluginChain []types.PluginConfig `json:"plugin_chain"`
}

func (r *UpdatePluginsRequest) Validate() error {
	if r.Type != "gateway" && r.Type != "rule" {
		return fmt.Errorf("type must be 'gateway' or 'rule'")
	}
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	return nil
}
