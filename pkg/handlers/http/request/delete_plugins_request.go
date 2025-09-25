package request

import "fmt"

type DeletePluginsRequest struct {
	Type    string   `json:"type"`
	ID      string   `json:"id"`
	Plugins []string `json:"plugins"`
}

func (r *DeletePluginsRequest) Validate() error {
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
		if p == "" {
			return fmt.Errorf("plugin name at index %d is empty", i)
		}
	}
	return nil
}
