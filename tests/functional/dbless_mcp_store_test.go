//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// startDBLessMCPPlane runs the MCP plane the way production does: no
// database, its config pulled over config sync and its Store writes made by the
// control plane.
func startDBLessMCPPlane(t *testing.T, port int, instanceID string) (string, *syncBuffer) {
	t.Helper()
	requireFreePorts([]int{port})
	overrides := []string{
		"CONFIG_SYNC_DATA_PLANE_ENABLED=true",
		"CONFIG_SYNC_GRPC_ENDPOINT=" + fmt.Sprintf("localhost:%d", serverConfigSyncGRPCPort),
		"CONFIG_SYNC_TLS_INSECURE=true",
		"CONFIG_SYNC_TOKEN=" + dblessConfigSyncToken,
		"CONFIG_SYNC_LKG_PATH=" + filepath.Join(t.TempDir(), "snapshot.lkg"),
		"CONFIG_SYNC_LKG_KEY=" + dblessLKGKey(),
		"CONFIG_SYNC_POLL_INTERVAL=1s",
		"CONFIG_SYNC_INSTANCE_ID=" + instanceID,
		"SERVER_MCP_PORT=" + strconv.Itoa(port),
		"OUTBOUND_ALLOW_PRIVATE_NETWORKS=true",
	}
	logs := &syncBuffer{}
	cmd := exec.Command(gatewayBinaryPath, "mcp") //nolint:gosec // controlled binary path
	cmd.Env = append(os.Environ(), overrides...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prefix := fmt.Sprintf("[DBLESS-MCP:%d] ", port)
	cmd.Stdout = io.MultiWriter(&prefixWriter{prefix: prefix, w: os.Stdout}, logs)
	cmd.Stderr = io.MultiWriter(&prefixWriter{prefix: prefix + "ERR ", w: os.Stderr}, logs)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	})
	base := fmt.Sprintf("http://localhost:%d", port)
	waitForDBLessLiveness(t, base)
	require.True(t, pollDBLessReady(base, 30*time.Second), "the db-less MCP plane never became ready")
	return base, logs
}

// storeMCPAt is storeMCPWith against a given MCP plane.
func storeMCPAt(t *testing.T, base, gatewayID, apiKey, method string, params map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, base+"/store/mcp", strings.NewReader(string(raw)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-AG-API-Key", apiKey)
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	req.Host = host.(string)
	return doJSONRequest(t, req)
}

// On the MCP plane as production runs it, a person with an OAuth server
// installed and not connected gets its connect link by installing it again —
// the install the plane forwards to the control plane — and opens the page.
func TestDBLessMCP_StoreConnectsAnInstalledServerThroughInstall(t *testing.T) {
	defer Track(t, "DBLessDataPlane")()
	idp := newOAuthProviderStub(t)
	upstream, _ := startCapturingMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("dbless-connect")})
	provider := uniqueName("linear")
	regID := CreateRegistry(t, gwID, mcpForwardedRegistryPayload(uniqueName("Linear"), upstream.URL, provider, idp))
	parsed, err := ids.Parse[ids.RegistryKind](regID)
	require.NoError(t, err)
	code := registrydomain.CustomStoreCode(parsed)
	alice := uniqueName("alice")

	status, granted := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s/store/grants", AdminURL, gwID), nil,
		map[string]any{"catalog_code": code, "users": []string{alice}})
	require.Equal(t, http.StatusOK, status, "body=%v", granted)
	status, installed := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/store/principal/installs", AdminURL, gwID), nil,
		map[string]any{"principal_sub": alice, "code": code})
	require.Equal(t, http.StatusOK, status, "body=%v", installed)
	// An administrator then turns installing off for alice. What she already
	// has stays hers, and connecting it is not installing.
	status, policy := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s/store/access-policies", AdminURL, gwID), nil,
		map[string]any{"principal_type": "user", "principal_id": alice, "mode": "none"})
	require.Equal(t, http.StatusOK, status, "body=%v", policy)
	status, issued := CreateLLMKey(t, gwID, alice, llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", issued)
	rawKey := fmt.Sprint(issued["api_key"])

	base, logs := startDBLessMCPPlane(t, GlobalConfig.Server.MCPPort+104, uniqueName("dbless-mcp"))

	// The key and the install reach the plane through its snapshot.
	var server map[string]any
	require.Eventually(t, func() bool {
		status, called := storeMCPAt(t, base, gwID, rawKey, "tools/call", map[string]any{
			"name": "trustgate_list_tools", "arguments": map[string]any{},
		})
		if status != http.StatusOK || called["error"] != nil {
			return false
		}
		result, _ := called["result"].(map[string]any)
		structured, _ := result["structuredContent"].(map[string]any)
		servers, _ := structured["servers"].([]any)
		if len(servers) != 1 {
			return false
		}
		server, _ = servers[0].(map[string]any)
		return true
	}, 30*time.Second, 300*time.Millisecond, "the db-less plane never listed the install; logs:\n%s", logs.String())
	require.Equal(t, "needs_connect", server["state"], "server=%v", server)
	require.Equal(t, "trustgate_store_install", server["connect_tool"], "server=%v", server)

	status, called := storeMCPAt(t, base, gwID, rawKey, "tools/call", map[string]any{
		"name": "trustgate_store_install", "arguments": map[string]any{"code": code},
	})
	require.Equal(t, http.StatusOK, status, "body=%v", called)
	require.Nil(t, called["error"], "installing again must answer the link; body=%v\nlogs:\n%s", called, logs.String())
	result, _ := called["result"].(map[string]any)
	structured, _ := result["structuredContent"].(map[string]any)
	link, err := url.Parse(fmt.Sprint(structured["connect_url"]))
	require.NoError(t, err, "body=%v", called)
	require.Equal(t, "/store/mcp/connect", link.Path, "body=%v", called)
	require.NotEmpty(t, link.Query().Get("ticket"))
}
