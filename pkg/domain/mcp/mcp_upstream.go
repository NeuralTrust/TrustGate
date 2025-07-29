package mcp

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ToolsRegistryJSON map[string]string

func (t ToolsRegistryJSON) Value() (driver.Value, error) {
	if t == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(t)
}

func (t *ToolsRegistryJSON) Scan(value interface{}) error {
	if value == nil {
		*t = make(ToolsRegistryJSON)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, t)
}

type Upstream struct {
	upstream.Upstream
	MCPServers    ServersJSON       `json:"mcp_servers" gorm:"type:jsonb"`
	ToolsRegistry ToolsRegistryJSON `json:"tools_registry" gorm:"type:jsonb"`
	SyncInterval  time.Duration     `json:"sync_interval,omitempty"`
}

func (m *Upstream) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	for i := range m.MCPServers {
		if m.MCPServers[i].ID == uuid.Nil {
			m.MCPServers[i].ID = uuid.New()
		}
		// Generate UUIDs for tools if they don't have them
		for j := range m.MCPServers[i].Tools {
			if m.MCPServers[i].Tools[j].ID == uuid.Nil {
				m.MCPServers[i].Tools[j].ID = uuid.New()
			}
			if m.MCPServers[i].Tools[j].ServerID == uuid.Nil {
				m.MCPServers[i].Tools[j].ServerID = m.MCPServers[i].ID
			}
			now := time.Now()
			if m.MCPServers[i].Tools[j].CreatedAt.IsZero() {
				m.MCPServers[i].Tools[j].CreatedAt = now
			}
			if m.MCPServers[i].Tools[j].UpdatedAt.IsZero() {
				m.MCPServers[i].Tools[j].UpdatedAt = now
			}
		}
	}
	if err := m.BuildToolsRegistry(); err != nil {
		return err
	}

	return m.Validate()
}

func (m *Upstream) BeforeUpdate(tx *gorm.DB) error {
	m.UpdatedAt = time.Now()
	if err := m.BuildToolsRegistry(); err != nil {
		return err
	}

	return m.Validate()
}

func (m *Upstream) BuildToolsRegistry() error {
	if m.ToolsRegistry == nil {
		m.ToolsRegistry = make(ToolsRegistryJSON)
	}
	for k := range m.ToolsRegistry {
		delete(m.ToolsRegistry, k)
	}
	for _, server := range m.MCPServers {
		for _, tool := range server.Tools {
			if existingServerID, exists := m.ToolsRegistry[tool.Name]; exists {
				return fmt.Errorf("tool name conflict: '%s' exists in both server '%s' and '%s'",
					tool.Name, existingServerID, server.ID.String())
			}
			m.ToolsRegistry[tool.Name] = server.ID.String()
		}
	}

	return nil
}

func (m *Upstream) Validate() error {
	if err := m.Upstream.Validate(); err != nil {
		return err
	}

	if len(m.MCPServers) == 0 {
		return fmt.Errorf("at least one MCP server is required")
	}

	serverIDs := make(map[string]bool)
	for i, server := range m.MCPServers {
		if err := server.Validate(); err != nil {
			return fmt.Errorf("MCP server %d validation failed: %w", i, err)
		}
		serverIDStr := server.ID.String()
		if serverIDs[serverIDStr] {
			return fmt.Errorf("duplicate MCP server ID: %s", server.ID)
		}
		serverIDs[serverIDStr] = true
	}

	if m.SyncInterval < 0 {
		return fmt.Errorf("sync interval cannot be negative")
	}

	return nil
}

func (m *Upstream) GetToolByName(toolName string) (*Tool, string, error) {
	serverID, exists := m.ToolsRegistry[toolName]
	if !exists {
		return nil, "", fmt.Errorf("tool '%s' not found", toolName)
	}

	for _, server := range m.MCPServers {
		if server.ID.String() == serverID {
			for _, tool := range server.Tools {
				if tool.Name == toolName {
					return &tool, serverID, nil
				}
			}
		}
	}

	return nil, "", fmt.Errorf("tool '%s' not found in server '%s'", toolName, serverID)
}

func (m *Upstream) GetServerByID(serverID string) (*Server, error) {
	for _, server := range m.MCPServers {
		if server.ID.String() == serverID {
			return &server, nil
		}
	}
	return nil, fmt.Errorf("MCP server '%s' not found", serverID)
}

func (m *Upstream) ListAllTools() []Tool {
	var allTools []Tool
	for _, server := range m.MCPServers {
		allTools = append(allTools, server.Tools...)
	}
	return allTools
}

func (m *Upstream) TableName() string {
	return "public.mcp_upstreams"
}
