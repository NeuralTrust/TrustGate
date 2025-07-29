package mcp

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Tool struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
	ServerID    uuid.UUID              `json:"server_id"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type ToolsJSON []Tool

func (m ToolsJSON) Value() (driver.Value, error) {
	if m == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(m)
}

func (m *ToolsJSON) Scan(value interface{}) error {
	if value == nil {
		*m = make(ToolsJSON, 0)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, m)
}
