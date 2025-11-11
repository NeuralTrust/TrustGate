package request

import "fmt"

type DeletePluginsRequest struct {
	Type      string   `json:"type"`
	ID        string   `json:"id"`
	PluginIds []string `json:"plugin_ids"`
}

func (r *DeletePluginsRequest) Validate() error {
	if r.Type != "gateway" && r.Type != "rule" {
		return fmt.Errorf("type must be 'gateway' or 'rule'")
	}
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if len(r.PluginIds) == 0 {
		return fmt.Errorf("plugin_ids is required")
	}
	for i, id := range r.PluginIds {
		if id == "" {
			return fmt.Errorf("plugin id at index %d is empty", i)
		}
	}
	return nil
}
