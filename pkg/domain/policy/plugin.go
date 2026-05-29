package policy

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// Stage represents the point in the request/response lifecycle at which a
// plugin executes. Values mirror the constants used by TrustGate to keep
// configuration portable across products.
type Stage string

const (
	StagePreRequest   Stage = "pre_request"
	StagePostRequest  Stage = "post_request"
	StagePreResponse  Stage = "pre_response"
	StagePostResponse Stage = "post_response"
)

func (s Stage) IsValid() bool {
	switch s {
	case StagePreRequest, StagePostRequest, StagePreResponse, StagePostResponse:
		return true
	default:
		return false
	}
}

// Plugin matches the TrustGate PluginConfig shape so a Policy can declare an
// ordered list of plugin executions that the proxy applies at runtime.
type Plugin struct {
	ID       string                 `json:"id,omitempty"`
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Stage    Stage                  `json:"stage"`
	Priority int                    `json:"priority"`
	Parallel bool                   `json:"parallel"`
	Settings map[string]interface{} `json:"settings,omitempty"`
}

func (p *Plugin) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidPlugin)
	}
	if !p.Stage.IsValid() {
		return fmt.Errorf("%w: %q", ErrInvalidStage, p.Stage)
	}
	return nil
}

// Plugins is the JSONB-serializable list of plugin configurations bound to
// a Policy. The ordering of the slice is preserved.
type Plugins []Plugin

func (p Plugins) Validate() error {
	seen := make(map[string]struct{}, len(p))
	for i := range p {
		if err := p[i].Validate(); err != nil {
			return fmt.Errorf("plugin %d: %w", i, err)
		}
		key := p[i].Name + "|" + string(p[i].Stage)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: %s at stage %s", ErrDuplicatePlugin, p[i].Name, p[i].Stage)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (p Plugins) Value() (driver.Value, error) {
	if len(p) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(p)
}

func (p *Plugins) Scan(value interface{}) error {
	if value == nil {
		*p = make(Plugins, 0)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	if len(bytes) == 0 {
		*p = make(Plugins, 0)
		return nil
	}
	return json.Unmarshal(bytes, p)
}
