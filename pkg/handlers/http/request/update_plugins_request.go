package request

import "fmt"

// UpdatePluginsRequest is used to update existing plugins in a gateway or rule by plugin ID.
// All provided plugin configs will replace the existing ones matched by ID.
// The handler will preserve the original ID and Name found in the chain, ignoring any differing
// values from the incoming request for those fields.
type UpdatePluginsRequest struct {
	Type    string           `json:"type"`
	ID      string           `json:"id"`
	Plugins []map[string]any `json:"plugins"`
}

func (r *UpdatePluginsRequest) Validate() error {
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
		id, ok := p["id"].(string)
		if !ok || id == "" {
			return fmt.Errorf("plugin id at index %d is required", i)
		}
	}
	return nil
}
