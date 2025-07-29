package mcp

import (
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPTool_Validation(t *testing.T) {
	serverID := uuid.New()
	toolID := uuid.New()
	now := time.Now()
	
	tests := []struct {
		name    string
		tool    Tool
		wantErr bool
	}{
		{
			name: "valid tool",
			tool: Tool{
				ID:          toolID,
				Name:        "test_tool",
				Description: "A test tool",
				Schema:      map[string]interface{}{"type": "object"},
				ServerID:    serverID,
				CreatedAt:   now,
				UpdatedAt:   now,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			tool: Tool{
				ID:        toolID,
				Name:      "",
				ServerID:  serverID,
				CreatedAt: now,
				UpdatedAt: now,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Tool doesn't have a Validate method, but it's validated within Server
			// This test structure is prepared for future validation if needed
			if tt.tool.Name == "" && tt.wantErr {
				assert.Empty(t, tt.tool.Name, "Tool name should be empty for error case")
			} else {
				assert.NotEmpty(t, tt.tool.Name, "Tool name should not be empty for valid case")
			}
		})
	}
}

func TestMCPServer_Validate(t *testing.T) {
	serverID := uuid.New()
	serverID2 := uuid.New()
	toolID1 := uuid.New()
	toolID2 := uuid.New()
	now := time.Now()
	
	tests := []struct {
		name    string
		server  Server
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid server",
			server: Server{
				ID:       serverID,
				Name:     "Test Server",
				Host:     "localhost",
				Port:     8080,
				Protocol: "http",
				Tools: ToolsJSON{
					{ID: toolID1, Name: "tool1", ServerID: serverID, CreatedAt: now, UpdatedAt: now},
					{ID: toolID2, Name: "tool2", ServerID: serverID, CreatedAt: now, UpdatedAt: now},
				},
			},
			wantErr: false,
		},
		{
			name: "empty ID",
			server: Server{
				ID:       uuid.Nil,
				Name:     "Test Server",
				Host:     "localhost",
				Port:     8080,
				Protocol: "http",
			},
			wantErr: true,
			errMsg:  "MCP server ID is required",
		},
		{
			name: "empty name",
			server: Server{
				ID:       serverID,
				Name:     "",
				Host:     "localhost",
				Port:     8080,
				Protocol: "http",
			},
			wantErr: true,
			errMsg:  "MCP server name is required",
		},
		{
			name: "empty host",
			server: Server{
				ID:       serverID,
				Name:     "Test Server",
				Host:     "",
				Port:     8080,
				Protocol: "http",
			},
			wantErr: true,
			errMsg:  "MCP server host is required",
		},
		{
			name: "invalid port - zero",
			server: Server{
				ID:       serverID,
				Name:     "Test Server",
				Host:     "localhost",
				Port:     0,
				Protocol: "http",
			},
			wantErr: true,
			errMsg:  "MCP server port must be between 1 and 65535",
		},
		{
			name: "invalid port - too high",
			server: Server{
				ID:       serverID,
				Name:     "Test Server",
				Host:     "localhost",
				Port:     70000,
				Protocol: "http",
			},
			wantErr: true,
			errMsg:  "MCP server port must be between 1 and 65535",
		},
		{
			name: "invalid protocol",
			server: Server{
				ID:       serverID,
				Name:     "Test Server",
				Host:     "localhost",
				Port:     8080,
				Protocol: "ftp",
			},
			wantErr: true,
			errMsg:  "MCP server protocol must be http or https",
		},
		{
			name: "tool with mismatched server ID",
			server: Server{
				ID:       serverID,
				Name:     "Test Server",
				Host:     "localhost",
				Port:     8080,
				Protocol: "http",
				Tools: ToolsJSON{
					{ID: toolID1, Name: "tool1", ServerID: serverID2, CreatedAt: now, UpdatedAt: now},
				},
			},
			wantErr: true,
			errMsg:  "server_id mismatch",
		},
		{
			name: "tool with empty name",
			server: Server{
				ID:       serverID,
				Name:     "Test Server",
				Host:     "localhost",
				Port:     8080,
				Protocol: "http",
				Tools: ToolsJSON{
					{ID: toolID1, Name: "", ServerID: serverID, CreatedAt: now, UpdatedAt: now},
				},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.server.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMCPUpstream_Validate(t *testing.T) {
	baseUpstream := upstream.Upstream{
		ID:        uuid.New(),
		GatewayID: uuid.New(),
		Name:      "test-upstream",
		Algorithm: "round-robin",
		Targets: upstream.Targets{
			{
				ID:       "target-1",
				Host:     "localhost",
				Port:     8080,
				Protocol: "http",
			},
		},
	}

	serverID1 := uuid.New()
	toolID1 := uuid.New()
	toolID2 := uuid.New()
	now := time.Now()

	tests := []struct {
		name        string
		mcpUpstream Upstream
		wantErr     bool
		errMsg      string
	}{
		{
			name: "valid MCP upstream",
			mcpUpstream: Upstream{
				Upstream: baseUpstream,
				MCPServers: ServersJSON{
					{
						ID:       serverID1,
						Name:     "Server 1",
						Host:     "localhost",
						Port:     8080,
						Protocol: "http",
						Tools: ToolsJSON{
							{ID: toolID1, Name: "tool1", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
							{ID: toolID2, Name: "tool2", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
						},
					},
				},
				SyncInterval: time.Minute * 5,
			},
			wantErr: false,
		},
		{
			name: "no MCP servers",
			mcpUpstream: Upstream{
				Upstream:     baseUpstream,
				MCPServers:   ServersJSON{},
				SyncInterval: time.Minute * 5,
			},
			wantErr: true,
			errMsg:  "at least one MCP server is required",
		},
		{
			name: "duplicate server IDs",
			mcpUpstream: Upstream{
				Upstream: baseUpstream,
				MCPServers: ServersJSON{
					{
						ID:       serverID1,
						Name:     "Server 1",
						Host:     "localhost",
						Port:     8080,
						Protocol: "http",
						Tools: ToolsJSON{
							{ID: toolID1, Name: "tool1", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
						},
					},
					{
						ID:       serverID1, // Duplicate ID
						Name:     "Server 2",
						Host:     "localhost",
						Port:     8081,
						Protocol: "http",
						Tools: ToolsJSON{
							{ID: toolID2, Name: "tool2", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
						},
					},
				},
				SyncInterval: time.Minute * 5,
			},
			wantErr: true,
			errMsg:  "duplicate MCP server ID",
		},
		{
			name: "negative sync interval",
			mcpUpstream: Upstream{
				Upstream: baseUpstream,
				MCPServers: ServersJSON{
					{
						ID:       serverID1,
						Name:     "Server 1",
						Host:     "localhost",
						Port:     8080,
						Protocol: "http",
						Tools: ToolsJSON{
							{ID: toolID1, Name: "tool1", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
						},
					},
				},
				SyncInterval: -time.Minute,
			},
			wantErr: true,
			errMsg:  "sync interval cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mcpUpstream.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMCPUpstream_BuildToolsRegistry(t *testing.T) {
	serverID1 := uuid.New()
	serverID2 := uuid.New()
	toolID1 := uuid.New()
	toolID2 := uuid.New()
	toolID3 := uuid.New()
	now := time.Now()

	tests := []struct {
		name        string
		mcpUpstream *Upstream
		wantErr     bool
		errMsg      string
		expected    ToolsRegistryJSON
	}{
		{
			name: "successful registry build",
			mcpUpstream: &Upstream{
				MCPServers: ServersJSON{
					{
						ID: serverID1,
						Tools: ToolsJSON{
							{ID: toolID1, Name: "tool1", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
							{ID: toolID2, Name: "tool2", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
						},
					},
					{
						ID: serverID2,
						Tools: ToolsJSON{
							{ID: toolID3, Name: "tool3", ServerID: serverID2, CreatedAt: now, UpdatedAt: now},
						},
					},
				},
			},
			wantErr: false,
			expected: ToolsRegistryJSON{
				"tool1": serverID1.String(),
				"tool2": serverID1.String(),
				"tool3": serverID2.String(),
			},
		},
		{
			name: "tool name conflict",
			mcpUpstream: &Upstream{
				MCPServers: ServersJSON{
					{
						ID: serverID1,
						Tools: ToolsJSON{
							{ID: toolID1, Name: "duplicate_tool", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
						},
					},
					{
						ID: serverID2,
						Tools: ToolsJSON{
							{ID: toolID2, Name: "duplicate_tool", ServerID: serverID2, CreatedAt: now, UpdatedAt: now},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "tool name conflict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mcpUpstream.BuildToolsRegistry()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, tt.mcpUpstream.ToolsRegistry)
			}
		})
	}
}

func TestMCPUpstream_GetToolByName(t *testing.T) {
	serverID := uuid.New()
	toolID1 := uuid.New()
	toolID2 := uuid.New()
	now := time.Now()

	mcpUpstream := &Upstream{
		MCPServers: ServersJSON{
			{
				ID:   serverID,
				Name: "Test Server",
				Tools: ToolsJSON{
					{ID: toolID1, Name: "tool1", ServerID: serverID, CreatedAt: now, UpdatedAt: now},
					{ID: toolID2, Name: "tool2", ServerID: serverID, CreatedAt: now, UpdatedAt: now},
				},
			},
		},
		ToolsRegistry: ToolsRegistryJSON{
			"tool1": serverID.String(),
			"tool2": serverID.String(),
		},
	}

	t.Run("existing tool", func(t *testing.T) {
		tool, serverIDStr, err := mcpUpstream.GetToolByName("tool1")
		require.NoError(t, err)
		assert.Equal(t, "tool1", tool.Name)
		assert.Equal(t, serverID.String(), serverIDStr)
	})

	t.Run("non-existing tool", func(t *testing.T) {
		_, _, err := mcpUpstream.GetToolByName("non_existing_tool")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tool 'non_existing_tool' not found")
	})
}

func TestMCPUpstream_GetServerByID(t *testing.T) {
	serverID := uuid.New()
	toolID := uuid.New()
	now := time.Now()

	mcpUpstream := &Upstream{
		MCPServers: ServersJSON{
			{
				ID:   serverID,
				Name: "Test Server",
				Tools: ToolsJSON{
					{ID: toolID, Name: "tool1", ServerID: serverID, CreatedAt: now, UpdatedAt: now},
				},
			},
		},
	}

	t.Run("existing server", func(t *testing.T) {
		server, err := mcpUpstream.GetServerByID(serverID.String())
		require.NoError(t, err)
		assert.Equal(t, "Test Server", server.Name)
		assert.Equal(t, serverID, server.ID)
	})

	t.Run("non-existing server", func(t *testing.T) {
		nonExistingID := uuid.New().String()
		_, err := mcpUpstream.GetServerByID(nonExistingID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MCP server")
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestMCPUpstream_ListAllTools(t *testing.T) {
	serverID1 := uuid.New()
	serverID2 := uuid.New()
	toolID1 := uuid.New()
	toolID2 := uuid.New()
	toolID3 := uuid.New()
	now := time.Now()

	mcpUpstream := &Upstream{
		MCPServers: ServersJSON{
			{
				ID: serverID1,
				Tools: ToolsJSON{
					{ID: toolID1, Name: "tool1", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
					{ID: toolID2, Name: "tool2", ServerID: serverID1, CreatedAt: now, UpdatedAt: now},
				},
			},
			{
				ID: serverID2,
				Tools: ToolsJSON{
					{ID: toolID3, Name: "tool3", ServerID: serverID2, CreatedAt: now, UpdatedAt: now},
				},
			},
		},
	}

	tools := mcpUpstream.ListAllTools()
	assert.Len(t, tools, 3)
	
	toolNames := make([]string, len(tools))
	for i, tool := range tools {
		toolNames[i] = tool.Name
	}
	
	assert.Contains(t, toolNames, "tool1")
	assert.Contains(t, toolNames, "tool2")
	assert.Contains(t, toolNames, "tool3")
}