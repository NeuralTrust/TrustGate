//go:build functional

package functional_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dblessConfigSyncToken = "functional-config-sync-token"

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
		"CONFIG_SYNC_GRPC_ENDPOINT=" + fmt.Sprintf("localhost:%d", serverConfigSyncGRPCPort),
		"CONFIG_SYNC_TLS_INSECURE=true",
		"CONFIG_SYNC_TOKEN=" + token,
		"CONFIG_SYNC_LKG_PATH=" + lkgPath,
		"CONFIG_SYNC_LKG_KEY=" + dblessLKGKey(),
		"CONFIG_SYNC_POLL_INTERVAL=2s",
		"CONFIG_SYNC_INSTANCE_ID=" + instanceID,
		"SERVER_PROXY_PORT=" + strconv.Itoa(port),
		// Upstream stubs listen on loopback.
		"OUTBOUND_ALLOW_PRIVATE_NETWORKS=true",
	}
}

func startDBLessProxyPlane(t *testing.T, port int, overrides []string) (string, *syncBuffer) {
	t.Helper()
	requireFreePorts([]int{port})

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
		snap, ok := b["snapshot"].(map[string]any)
		require.True(t, ok, "readiness must expose the snapshot state: %v", b)
		assert.Equal(t, "none", snap["state"], "snapshot state must be none without a snapshot: %v", b)
		_, hasPostgres := deps["postgres"]
		assert.False(t, hasPostgres, "db-less plane must not expose a postgres dependency: %v", b)
		time.Sleep(300 * time.Millisecond)
	}
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
	snap, ok := ready["snapshot"].(map[string]any)
	require.True(t, ok, "readiness body must expose the snapshot state: %v", ready)
	assert.Equal(t, "live", snap["state"], "snapshot state must be live after a converge: %v", ready)
	assert.NotContains(t, snap, "version", "snapshot version must not be exposed on an unauthenticated probe: %v", ready)
	assert.Contains(t, snap, "age_seconds", "snapshot age must be reported: %v", ready)
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

func pollProxyStatusAt(t *testing.T, base, apiKey, path string, body any, want int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, _, _ := proxyPostAt(t, base, apiKey, path, body)
		if status == want {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// TestDBLessDataPlane_ConvergesOnInPlaceEditOfServedGateway guards the failure
// mode where the data plane keeps serving a stale, cache-warmed configuration
// after an in-place edit to an already-served gateway. Creating new gateways
// is not enough: the derived caches keyed by an existing gateway must also be
// dropped when a new snapshot version is applied, or edits never take effect
// until the process restarts.
func TestDBLessDataPlane_ConvergesOnInPlaceEditOfServedGateway(t *testing.T) {
	defer Track(t, "DBLessDataPlane")()

	upstream := newJSONUpstream(t, "dbless-inplace-marker")
	secret := "sk-dbless-inplace-" + uuid.NewString()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("dbless-inplace-gw")})
	registryID := CreateRegistry(t, gatewayID, dblessBackendPayload(uniqueName("be"), upstream.URL(), secret))
	consumerName := uniqueName("cons")
	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": consumerName,
		"registries": []map[string]any{
			{"id": registryID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}}},
		},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := chatCompletionsPath(t, coID)

	port := GlobalConfig.Server.ProxyPort + 102
	lkgPath := filepath.Join(t.TempDir(), "snapshot.lkg")
	base, _ := startDBLessProxyPlane(t, port,
		dblessOverrides(lkgPath, dblessConfigSyncToken, uniqueName("dbless-inplace"), port))
	require.True(t, pollDBLessReady(base, 30*time.Second),
		"db-less plane never became ready after the first snapshot pull")

	require.True(t, pollProxyStatusAt(t, base, apiKey, path, chatRequestModel("gpt-4o-mini"), http.StatusOK, 30*time.Second),
		"db-less plane never converged to serve the allowed model")

	warm, _, warmBody := proxyPostAt(t, base, apiKey, path, chatRequestModel("gpt-4o-mini"))
	require.Equal(t, http.StatusOK, warm, "the allowed model must be served, warming the gateway-scoped caches: %s", warmBody)

	UpdateConsumer(t, gatewayID, coID, map[string]any{
		"name": consumerName,
		"model_policies": []map[string]any{
			{"registry_id": registryID, "allowed": []string{"gpt-4o-restricted-only"}},
		},
	})

	consumerURL := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gatewayID, coID)
	getStatus, getBody := sendRequest(t, http.MethodGet, consumerURL, nil, nil)
	require.Equal(t, http.StatusOK, getStatus, "admin must return the edited consumer: %v", getBody)
	require.Contains(t, fmt.Sprintf("%v", getBody), "gpt-4o-restricted-only",
		"control plane must persist the tightened model policy for the existing gateway: %v", getBody)

	require.True(t, pollProxyStatusAt(t, base, apiKey, path, chatRequestModel("gpt-4o-mini"), http.StatusForbidden, 30*time.Second),
		"db-less plane never converged to the in-place model-policy edit; a cache keyed by the existing gateway stayed warm")
}

type countingProxy struct {
	listener net.Listener
	bytes    atomic.Int64
}

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countingWriter) Write(b []byte) (int, error) {
	c.n.Add(int64(len(b)))
	return c.w.Write(b)
}

func startCountingProxy(t *testing.T, target string) *countingProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &countingProxy{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.pipe(conn, target)
		}
	}()
	return p
}

func (p *countingProxy) pipe(client net.Conn, target string) {
	defer func() { _ = client.Close() }()
	server, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = server.Close() }()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(countingWriter{w: server, n: &p.bytes}, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(countingWriter{w: client, n: &p.bytes}, server); done <- struct{}{} }()
	<-done
}

func (p *countingProxy) quiet(t *testing.T) int64 {
	t.Helper()
	last := p.bytes.Load()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		time.Sleep(time.Second)
		now := p.bytes.Load()
		if now == last {
			return now
		}
		last = now
	}
	t.Fatal("the config-sync connection never went quiet")
	return 0
}

func TestDBLessDataPlane_LLMStore(t *testing.T) {
	defer Track(t, "DBLessDataPlane")()
	f := setupStoreFixture(t, map[string]any{"slug": uniqueName("dbless-store")})
	configSync := startCountingProxy(t, fmt.Sprintf("localhost:%d", serverConfigSyncGRPCPort))
	port := GlobalConfig.Server.ProxyPort + 103
	overrides := append(dblessOverrides(filepath.Join(t.TempDir(), "snapshot.lkg"), dblessConfigSyncToken, uniqueName("dbless-store"), port),
		"CONFIG_SYNC_GRPC_ENDPOINT="+configSync.listener.Addr().String(), "CONFIG_SYNC_POLL_INTERVAL=1h", "CONFIG_SYNC_GRPC_KEEPALIVE_TIME=1h")
	base, _ := startDBLessProxyPlane(t, port, overrides)
	require.True(t, pollDBLessReady(base, 30*time.Second), "db-less plane never became ready after the first snapshot pull")
	eventuallyStore(t, storeServes(t, base, f, "gpt6", http.StatusOK, "store-d-openai"), "the db-less plane never served the store")

	assertWorkedExample(t, base, f)

	settled := configSync.quiet(t)
	require.Positive(t, settled, "the db-less plane syncs through the counting proxy")
	status, body := storeChat(t, base, f.gatewayID, f.key, "gpt6")
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, "store-d-openai")
	assert.Equal(t, settled, configSync.bytes.Load(), "a warm store request makes no config-sync call")

	AttachAuthLink(t, f.gatewayID, f.consumers["B"], f.keyID, "group", 0, time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC))
	eventuallyStore(t, storeServes(t, base, f, "opus-5.5", http.StatusForbidden, storeGuard("B")),
		"the priority change never reached the db-less plane")

	for _, name := range []string{"A", "B", "D"} {
		DetachAuth(t, f.gatewayID, f.consumers[name], f.keyID)
	}
	eventuallyStore(t, func() bool {
		cards := storeModels(t, base, f.gatewayID, f.key)
		return len(cards) == 1 && cards["opus-5.5"] == "anthropic"
	}, "after the detaches the db-less listing holds only C's model")

	status, _ = sendRequest(t, http.MethodDelete, fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, f.gatewayID, f.keyID), nil, nil)
	require.Equal(t, http.StatusNoContent, status)
	eventuallyStore(t, func() bool { return storeModelsStatus(t, base, f.gatewayID, f.key) == http.StatusUnauthorized },
		"the admin revocation never reached the db-less plane")
}
