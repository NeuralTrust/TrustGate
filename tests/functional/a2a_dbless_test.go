//go:build functional

package functional_test

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startDBLessAgentPlane runs the agent plane as production does: no database,
// its config pulled over config sync.
func startDBLessAgentPlane(t *testing.T, port int, instanceID string) (string, *syncBuffer) {
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
		"SERVER_AGENT_PORT=" + strconv.Itoa(port),
		"OUTBOUND_ALLOW_PRIVATE_NETWORKS=true",
		"STS_SIGNING_KEY=" + functionalSTSSigningKey,
	}
	logs := &syncBuffer{}
	cmd := exec.Command(gatewayBinaryPath, "agent") //nolint:gosec // controlled binary path
	cmd.Env = append(os.Environ(), overrides...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prefix := fmt.Sprintf("[DBLESS-AGENT:%d] ", port)
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
	require.True(t, pollDBLessReady(base, 30*time.Second), "the db-less agent plane never became ready")
	return base, logs
}

// A DB-less agent plane serves an agent from its snapshot: card, send, get,
// stream, ownership and refusals, as the Postgres-backed plane does.
func TestDBLessA2A_ServesAgentsFromTheSnapshot(t *testing.T) {
	defer Track(t, "DBLessDataPlane")()
	const version = "1.0"
	agent := startFakeAgent(t, version)
	methods := a2aMethods[version]
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("dbless-a2a")})
	registryID := CreateRegistry(t, gatewayID, a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, version,
		map[string]any{"mode": "static", "header": "X-Agent-Key", "value": "agent-secret"}))
	consumerA, keyA := createA2AConsumer(t, gatewayID, registryID)
	consumerB, keyB := createA2AConsumer(t, gatewayID, registryID)
	pathA, pathB := agentPath(t, consumerA, registryID), agentPath(t, consumerB, registryID)

	base, logs := startDBLessAgentPlane(t, GlobalConfig.Server.AgentPort+104, uniqueName("dbless-agent"))

	require.Eventually(t, func() bool {
		resp := agentRequest(t, base, gatewayID, http.MethodGet, pathA+"/.well-known/agent-card.json", a2aKey(keyA), nil)
		return resp.StatusCode == http.StatusOK
	}, 30*time.Second, 300*time.Millisecond, "the db-less plane never served the card; logs:\n%s", logs.String())

	status, sent := a2aRPC(t, base, gatewayID, pathA, a2aKey(keyA), methods["send"], a2aMessage(version, "hello", ""))
	require.Equal(t, http.StatusOK, status, "body=%v", sent)
	taskID := a2aTask(t, version, sent)["id"]
	assert.Equal(t, "agent-secret", agent.last().Header.Get("X-Agent-Key"), "the registry's secret reaches the plane through the snapshot")

	status, body := a2aRPC(t, base, gatewayID, pathA, a2aKey(keyA), methods["get"], map[string]any{"id": taskID})
	require.Equal(t, http.StatusOK, status)
	assert.Nil(t, body["error"], "body=%v", body)

	before := agent.count()
	status, body = a2aRPC(t, base, gatewayID, pathB, a2aKey(keyB), methods["get"], map[string]any{"id": taskID})
	assert.Equal(t, -32001, a2aErrorCode(t, status, body))
	status, body = a2aRPC(t, base, gatewayID, pathA, a2aKey(keyA), methods["push"], map[string]any{"taskId": taskID})
	assert.Equal(t, -32003, a2aErrorCode(t, status, body))
	assert.Equal(t, before, agent.count())

	events := a2aStream(t, base, gatewayID, pathA, a2aKey(keyA), methods["stream"], a2aMessage(version, "streamed", ""))
	require.Len(t, events, 4, "events=%v", events)
	assert.Contains(t, fmt.Sprint(events[2]["result"]), "echo: streamed")
}
