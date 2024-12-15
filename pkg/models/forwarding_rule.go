package models

import (
	"ai-gateway-ce/pkg/types"
	"database/sql/driver"
	"encoding/json"
	"time"
)

type ForwardingRule struct {
	ID            string          `json:"id"`
	GatewayID     string          `json:"gateway_id"`
	Path          string          `json:"path"`
	Targets       TargetsJSON     `json:"targets" gorm:"type:jsonb"`
	Methods       MethodsJSON     `json:"methods" gorm:"type:jsonb"`
	Headers       HeadersJSON     `json:"headers" gorm:"type:jsonb"`
	StripPath     bool            `json:"strip_path"`
	PreserveHost  bool            `json:"preserve_host"`
	RetryAttempts int             `json:"retry_attempts"`
	PluginChain   PluginChainJSON `json:"plugin_chain" gorm:"type:jsonb"`
	Active        bool            `json:"active"`
	Public        bool            `json:"public"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// TargetsJSON implements SQL/JSON conversion for []types.ForwardingTarget
type TargetsJSON []types.ForwardingTarget

// Value implements the driver.Valuer interface
func (t TargetsJSON) Value() (driver.Value, error) {
	if t == nil {
		return nil, nil
	}
	return json.Marshal(t)
}

// Scan implements the sql.Scanner interface
func (t *TargetsJSON) Scan(value interface{}) error {
	if value == nil {
		*t = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &t)
	}
	return json.Unmarshal(bytes, &t)
}

// MethodsJSON implements SQL/JSON conversion for []string
type MethodsJSON []string

// Value implements the driver.Valuer interface
func (m MethodsJSON) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// Scan implements the sql.Scanner interface
func (m *MethodsJSON) Scan(value interface{}) error {
	if value == nil {
		*m = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &m)
	}
	return json.Unmarshal(bytes, &m)
}

// PluginChainJSON implements SQL/JSON conversion for []types.PluginConfig
type PluginChainJSON []types.PluginConfig

// Value implements the driver.Valuer interface
func (p PluginChainJSON) Value() (driver.Value, error) {
	if p == nil {
		return nil, nil
	}
	return json.Marshal(p)
}

// Scan implements the sql.Scanner interface
func (p *PluginChainJSON) Scan(value interface{}) error {
	if value == nil {
		*p = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &p)
	}
	return json.Unmarshal(bytes, &p)
}

// HeadersJSON implements SQL/JSON conversion for map[string]string
type HeadersJSON map[string]string

// Value implements the driver.Valuer interface
func (h HeadersJSON) Value() (driver.Value, error) {
	if h == nil {
		return nil, nil
	}
	return json.Marshal(h)
}

// Scan implements the sql.Scanner interface
func (h *HeadersJSON) Scan(value interface{}) error {
	if value == nil {
		*h = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &h)
	}
	return json.Unmarshal(bytes, &h)
}

// TableName specifies the table name for GORM
func (ForwardingRule) TableName() string {
	return "forwarding_rules"
}
