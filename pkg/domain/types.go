package domain

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type (
	MethodsJSON     []string
	HeadersJSON     map[string]string
	PluginChainJSON []types.PluginConfig
	CredentialsJSON types.Credentials
	TagsJSON        []string
)

func (m MethodsJSON) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

func (m *MethodsJSON) Scan(value interface{}) error {
	if value == nil {
		*m = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, m)
}

func (h HeadersJSON) Value() (driver.Value, error) {
	if h == nil {
		return nil, nil
	}
	return json.Marshal(h)
}

func (h *HeadersJSON) Scan(value interface{}) error {
	if value == nil {
		*h = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, h)
}

func (p PluginChainJSON) Value() (driver.Value, error) {
	if p == nil {
		return nil, nil
	}
	return json.Marshal(p)
}

func (p *PluginChainJSON) Scan(value interface{}) error {
	if value == nil {
		*p = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, p)
}

func (c CredentialsJSON) Value() (driver.Value, error) {
	return json.Marshal(c)
}

func (c *CredentialsJSON) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, c)
}

func (t TagsJSON) Value() (driver.Value, error) {
	if t == nil {
		return nil, nil
	}
	return json.Marshal(t)
}

func (t *TagsJSON) Scan(value interface{}) error {
	if value == nil {
		*t = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, t)
}
