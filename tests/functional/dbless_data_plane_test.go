//go:build functional

package functional_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	dblessConfigSyncToken = "functional-config-sync-token"
	configSnapshotPath    = "/internal/config/snapshot"
)

func dblessLKGKey() string {
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func dblessOverrides(lkgPath, token, instanceID string, port int) []string {
	return []string{
		"CONFIG_SYNC_DATA_PLANE_ENABLED=true",
		"CONFIG_SYNC_SNAPSHOT_URL=" + AdminURL + configSnapshotPath,
		"CONFIG_SYNC_TOKEN=" + token,
		"CONFIG_SYNC_LKG_PATH=" + lkgPath,
		"CONFIG_SYNC_LKG_KEY=" + dblessLKGKey(),
		"CONFIG_SYNC_POLL_INTERVAL=2s",
		"CONFIG_SYNC_INSTANCE_ID=" + instanceID,
		"SERVER_PROXY_PORT=" + strconv.Itoa(port),
	}
}

func startDBLessProxyPlane(t *testing.T, port int, overrides []string) (string, *syncBuffer) {
	t.Helper()
	killProcessesOnPorts([]int{port})

	logs := &syncBuffer{}
	cmd := exec.Command(gatewayBinaryPath, "proxy") //nolint:gosec // controlled binary path
	cmd.Env = append(os.Environ(), overrides...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prefix := fmt.Sprintf("[DBLESS:%d] ", port)
	cmd.Stdout = io.MultiWriter(&prefixWriter{prefix: prefix, w: os.Stdout}, logs)
	cmd.Stderr = io.MultiWriter(&prefixWriter{prefix: prefix + "ERR ", w: os.Stderr}, logs)

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start db-less proxy plane: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	})

	base := fmt.Sprintf("http://localhost:%d", port)
	waitForDBLessLiveness(t, base)
	return base, logs
}

func waitForDBLessLiveness(t *testing.T, base string) {
	t.Helper()
	for i := 0; i < 150; i++ {
		resp, err := http.Get(base + "/healthz") //nolint:gosec // controlled URL
		if err == nil {
			code := resp.StatusCode
			_ = resp.Body.Close()
			if code == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("db-less proxy plane at %s never reported liveness", base)
}

func pollDBLessReady(base string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/readyz") //nolint:gosec // controlled URL
		if err == nil {
			code := resp.StatusCode
			_ = resp.Body.Close()
			if code == http.StatusOK {
				return true
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func proxyPostAt(t *testing.T, base, apiKey, path string, body any) (int, http.Header, []byte) {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(buf))
	require.NoError(t, err)
	host, ok := proxyHosts.Load(apiKey)
	require.True(t, ok, "proxy host missing for api key")
	req.Host = host.(string)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxyAPIKeyHeader, apiKey)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, raw
}

func pollProxyServedAt(t *testing.T, base, apiKey, path, marker string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, _, body := proxyPostAt(t, base, apiKey, path, chatRequest(false))
		if status == http.StatusOK && strings.Contains(string(body), marker) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func dblessBackendPayload(name, baseURL, secret string) map[string]any {
	return map[string]any{
		"name":             name,
		"provider":         "openai",
		"weight":           1,
		"provider_options": map[string]any{"base_url": baseURL},
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": secret},
		},
	}
}

func TestDBLessDataPlane_ReadinessGatedOnSnapshotAndLivenessIndependent(t *testing.T) {
	defer Track(t, "DBLessDataPlane")()

	port := GlobalConfig.Server.ProxyPort + 100
	lkgPath := filepath.Join(t.TempDir(), "snapshot.lkg")
	base, _ := startDBLessProxyPlane(t, port,
		dblessOverrides(lkgPath, "wrong-config-sync-token", uniqueName("dbless-unready"), port))

	status, body := sendRequest(t, http.MethodGet, base+"/healthz", nil, nil)
	require.Equal(t, http.StatusOK, status, "liveness must not depend on snapshot presence: %v", body)
	assert.Equal(t, "healthy", body["status"])

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		s, b := sendRequest(t, http.MethodGet, base+"/readyz", nil, nil)
		require.Equal(t, http.StatusServiceUnavailable, s, "readiness must stay not-ready without a snapshot: %v", b)
		require.Equal(t, "not_ready", b["status"], "readiness state must be not_ready without a snapshot: %v", b)
		deps, ok := b["dependencies"].(map[string]any)
		require.True(t, ok, "readiness must expose dependencies: %v", b)
		assert.Equal(t, "unavailable", deps["snapshot"], "snapshot dependency must be unavailable: %v", b)
		_, hasPostgres := deps["postgres"]
		assert.False(t, hasPostgres, "db-less plane must not expose a postgres dependency: %v", b)
		time.Sleep(300 * time.Millisecond)
	}
}

func TestDBLessDataPlane_SnapshotEndpointFailsClosed(t *testing.T) {
	defer Track(t, "DBLessDataPlane")()

	noTokenStatus, noTokenBody := sendRequest(t, http.MethodGet, AdminURL+configSnapshotPath,
		map[string]string{"Authorization": ""}, nil)
	require.Equal(t, http.StatusUnauthorized, noTokenStatus,
		"snapshot endpoint must reject a request with no config-sync token: %v", noTokenBody)

	wrongTokenStatus, wrongTokenBody := sendRequest(t, http.MethodGet, AdminURL+configSnapshotPath,
		map[string]string{"Authorization": "Bearer not-the-token"}, nil)
	require.Equal(t, http.StatusUnauthorized, wrongTokenStatus,
		"snapshot endpoint must reject an invalid config-sync token: %v", wrongTokenBody)

	authHeaders := map[string]string{"Authorization": "Bearer " + dblessConfigSyncToken}
	var (
		status int
		etag   string
		ctype  string
		raw    []byte
	)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, AdminURL+configSnapshotPath, nil)
		require.NoError(t, err)
		for k, v := range authHeaders {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		status = resp.StatusCode
		etag = resp.Header.Get("ETag")
		ctype = resp.Header.Get("Content-Type")
		raw, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if status == http.StatusOK {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	require.Equal(t, http.StatusOK, status, "authenticated snapshot pull must eventually succeed")
	require.NotEmpty(t, etag, "a 200 snapshot response must carry an ETag version")
	assert.True(t, strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`), "ETag must be a quoted version: %q", etag)
	assert.Equal(t, "application/x-protobuf", ctype, "snapshot must be served as protobuf")
	require.NotEmpty(t, raw, "a 200 snapshot response must carry a protobuf body")
}

func TestDBLessDataPlane_ConvergesServesAtParityAndKeepsSecretsOutOfLogs(t *testing.T) {
	defer Track(t, "DBLessDataPlane")()

	upstream := newJSONUpstream(t, "dbless-parity-marker")
	secret := "sk-dbless-" + uuid.NewString()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("dbless-gw")})
	registryID := CreateRegistry(t, gatewayID, dblessBackendPayload(uniqueName("be"), upstream.URL(), secret))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := chatCompletionsPath(t, coID)

	policyUp := newJSONUpstream(t, "dbless-policy-marker")
	policyKey, policyPath := setupModelPolicyRoute(t, policyUp, []string{"gpt-4o-mini"}, "")

	pgStatus, pgHeaders, pgBody := proxyPost(t, apiKey, path, chatRequest(false))
	require.Equal(t, http.StatusOK, pgStatus, "postgres proxy must serve the new gateway: %s", pgBody)
	require.Contains(t, string(pgBody), "dbless-parity-marker")
	require.Equal(t, "openai", pgHeaders.Get("X-Selected-Provider"))

	pgPolicyStatus, _, pgPolicyBody := proxyPost(t, policyKey, policyPath, chatRequestModel("gpt-4-forbidden"))
	require.Equal(t, http.StatusForbidden, pgPolicyStatus, "postgres proxy must reject a disallowed model: %s", pgPolicyBody)

	port := GlobalConfig.Server.ProxyPort + 101
	lkgPath := filepath.Join(t.TempDir(), "snapshot.lkg")
	base, logs := startDBLessProxyPlane(t, port,
		dblessOverrides(lkgPath, dblessConfigSyncToken, uniqueName("dbless-parity"), port))

	require.True(t, pollDBLessReady(base, 30*time.Second),
		"db-less plane never became ready after the first snapshot pull")

	_, ready := sendRequest(t, http.MethodGet, base+"/readyz", nil, nil)
	deps, ok := ready["dependencies"].(map[string]any)
	require.True(t, ok, "readiness body must expose dependencies: %v", ready)
	assert.Equal(t, "ok", deps["snapshot"], "snapshot dependency must be ok once converged: %v", ready)
	_, hasPostgres := deps["postgres"]
	assert.False(t, hasPostgres, "db-less plane must not expose a postgres dependency: %v", ready)

	require.True(t, pollProxyServedAt(t, base, apiKey, path, "dbless-parity-marker", 30*time.Second),
		"db-less plane never converged to serve the control-plane gateway")

	dbStatus, dbHeaders, dbBody := proxyPostAt(t, base, apiKey, path, chatRequest(false))
	require.Equal(t, http.StatusOK, dbStatus, "db-less plane must serve at parity: %s", dbBody)
	require.Contains(t, string(dbBody), "dbless-parity-marker")
	assert.Equal(t, pgHeaders.Get("X-Selected-Provider"), dbHeaders.Get("X-Selected-Provider"),
		"provider selection must match the postgres path")

	dbPolicyStatus, _, dbPolicyBody := proxyPostAt(t, base, policyKey, policyPath, chatRequestModel("gpt-4-forbidden"))
	require.Equal(t, http.StatusForbidden, dbPolicyStatus,
		"db-less plane must reject a disallowed model from the precomputed policy plan: %s", dbPolicyBody)

	newUpstream := newJSONUpstream(t, "dbless-onwrite-marker")
	newSecret := "sk-dbless-onwrite-" + uuid.NewString()
	newGatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("dbless-onwrite-gw")})
	newRegistryID := CreateRegistry(t, newGatewayID, dblessBackendPayload(uniqueName("be"), newUpstream.URL(), newSecret))
	newCoID := CreateConsumer(t, newGatewayID, map[string]any{"name": uniqueName("cons")})
	AttachRegistry(t, newGatewayID, newCoID, newRegistryID)
	newAPIKey := createAndAttachAPIKey(t, newGatewayID, newCoID)
	newPath := chatCompletionsPath(t, newCoID)

	require.True(t, pollProxyServedAt(t, base, newAPIKey, newPath, "dbless-onwrite-marker", 30*time.Second),
		"db-less plane never converged after a control-plane write signalled a new snapshot version")

	captured := logs.String()
	assert.NotContains(t, captured, secret, "the db-less plane must never log a snapshot registry credential")
	assert.NotContains(t, captured, newSecret, "the db-less plane must never log a snapshot registry credential")
}
