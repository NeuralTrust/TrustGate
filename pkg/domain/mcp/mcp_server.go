package mcp

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
)

type Server struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Host        string                 `json:"host"`
	Port        int                    `json:"port"`
	Protocol    string                 `json:"protocol"` // http/https
	BasePath    string                 `json:"base_path,omitempty"`
	Headers     domain.HeadersJSON     `json:"headers,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
	Tools       ToolsJSON              `json:"tools,omitempty"` // Cache of tools
	LastSync    time.Time              `json:"last_sync"`
	Credentials domain.CredentialsJSON `json:"credentials,omitempty"`
}

func (s *Server) Validate() error {
	if s.ID == uuid.Nil {
		return fmt.Errorf("MCP server ID is required")
	}
	if s.Name == "" {
		return fmt.Errorf("MCP server name is required")
	}
	if s.Host == "" {
		return fmt.Errorf("MCP server host is required")
	}
	if s.Port <= 0 || s.Port > 65535 {
		return fmt.Errorf("MCP server port must be between 1 and 65535")
	}
	if s.Protocol != "http" && s.Protocol != "https" {
		return fmt.Errorf("MCP server protocol must be http or https")
	}

	for i, tool := range s.Tools {
		if tool.Name == "" {
			return fmt.Errorf("MCP tool %d: name is required", i)
		}
		if tool.ServerID != s.ID {
			return fmt.Errorf("MCP tool %d: server_id mismatch", i)
		}
	}

	return nil
}

type ServersJSON []Server

func (m ServersJSON) Value() (driver.Value, error) {
	if m == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(m)
}

func (m *ServersJSON) Scan(value interface{}) error {
	if value == nil {
		*m = make(ServersJSON, 0)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, m)
}
