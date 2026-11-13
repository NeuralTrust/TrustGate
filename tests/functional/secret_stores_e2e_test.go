//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// functionalConfigSyncJWTSecret signs the gateway-scoped config-sync tokens a
// hybrid data plane presents. The suite's admin runs in composite mode, so
// the shared token keeps working for the in-cluster planes.
const (
	functionalConfigSyncJWTSecret   = "functional-config-sync-jwt-secret-0123456789abcdef"
	functionalConfigSyncJWTIssuer   = "functional-console"
	functionalConfigSyncJWTAudience = "trustgate-config-sync"
)

const (
	vaultTestToken = "functional-vault-token"
	vaultTestPath  = "ai-gateway/openai"
)

// fakeVault serves KV v2 reads of one secret and token lookups, behind a
// static token. It can rotate the secret and go down.
type fakeVault struct {
	server  *httptest.Server
	mu      sync.Mutex
	apiKey  string
	version int
	down    bool
	reads   atomic.Int64
}

func newFakeVault(t *testing.T, apiKey string) *fakeVault {
	t.Helper()
	v := &fakeVault{apiKey: apiKey, version: 1}
	v.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		down, key, version := v.down, v.apiKey, v.version
		v.mu.Unlock()
		if r.Header.Get("X-Vault-Token") != vaultTestToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			_, _ = io.WriteString(w, `{"data":{"ttl":0}}`)
		case "/v1/secret/data/" + vaultTestPath:
			v.reads.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"data":     map[string]any{"api_key": key},
				"metadata": map[string]any{"version": version},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(v.server.Close)
	return v
}

func (v *fakeVault) rotate(apiKey string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.apiKey, v.version = apiKey, v.version+1
}

func (v *fakeVault) setDown(down bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.down = down
}

// keyedUpstream is an OpenAI-compatible upstream that accepts only the
// current API key and answers 401 to any other.
type keyedUpstream struct {
	server   *httptest.Server
	mu       sync.Mutex
	expected string
	seen     []string
}

func newKeyedUpstream(t *testing.T, apiKey, marker string) *keyedUpstream {
	t.Helper()
	u := &keyedUpstream{expected: apiKey}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		u.mu.Lock()
		u.seen = append(u.seen, got)
		ok := got == u.expected
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if ok && strings.HasSuffix(r.URL.Path, "/models") {
			_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"gpt-4o-mini","object":"model"}]}`)
			return
		}
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"message":"invalid api key","type":"invalid_request_error"}}`)
			return
		}
		_, _ = fmt.Fprintf(w,
			`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`,
			marker)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *keyedUpstream) expect(apiKey string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.expected = apiKey
}

func (u *keyedUpstream) keysSeen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.seen...)
}

// mintConfigSyncScopedToken signs the token a hybrid data plane of gatewayID
// presents to config-sync.
func mintConfigSyncScopedToken(t *testing.T, gatewayID string) string {
	t.Helper()
	token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, golangjwt.MapClaims{
		"scope": gatewayID,
		"iss":   functionalConfigSyncJWTIssuer,
		"aud":   functionalConfigSyncJWTAudience,
		"jti":   uuid.NewString(),
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(functionalConfigSyncJWTSecret))
	require.NoError(t, err)
	return token
}

func writeVaultStoreFile(t *testing.T, vaultURL string) string {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "vault-token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(vaultTestToken), 0o600))
	storeFile := filepath.Join(dir, "secret-stores.yaml")
	require.NoError(t, os.WriteFile(storeFile, []byte(fmt.Sprintf(`version: 1
stores:
  - name: corp-vault
    type: hashicorp_vault
    allowed_paths: ["ai-gateway/"]
    hashicorp_vault:
      address: %s
      auth:
        method: token
        token_file: %s
`, vaultURL, tokenFile)), 0o600))
	return storeFile
}

func secretStoresListing(t *testing.T, gatewayID string) map[string]any {
	t.Helper()
	status, body := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/v1/gateways/%s/secret-stores", AdminURL, gatewayID), nil, nil)
	require.Equal(t, http.StatusOK, status, "list secret stores: %v", body)
	return body
}

func storeStatus(listing map[string]any, name string) string {
	stores, _ := listing["stores"].([]any)
	for _, s := range stores {
		if m, ok := s.(map[string]any); ok && m["name"] == name {
			status, _ := m["status"].(string)
			return status
		}
	}
	return ""
}

func postJSONStatus(t *testing.T, url string, headers map[string]string, body any) (int, []byte) {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func TestSecretStoresHybridE2E(t *testing.T) {
	defer Track(t, "SecretStores")()

	key1 := "sk-vault-one-" + uuid.NewString()
	key2 := "sk-vault-two-" + uuid.NewString()
	vault := newFakeVault(t, key1)
	upstream := newKeyedUpstream(t, key1, "secret-stores-marker")

	plan := functionalSuitePlan()
	plan["data_plane"] = "hybrid"
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("vault-gw"), "entitlements": plan})

	port := GlobalConfig.Server.ProxyPort + 140
	lkgPath := filepath.Join(t.TempDir(), "snapshot.lkg")
	overrides := append(dblessOverrides(lkgPath, mintConfigSyncScopedToken(t, gatewayID), uniqueName("vault-dp"), port),
		"SECRET_STORES_FILE="+writeVaultStoreFile(t, vault.server.URL),
		"SECRET_STORES_PROBE_INTERVAL=1s",
		"SECRET_STORES_READINESS_GATE=true",
		"CONFIG_SYNC_HEARTBEAT_INTERVAL=1s",
	)
	base, logs := startDBLessProxyPlane(t, port, overrides)

	require.Eventually(t, func() bool {
		listing := secretStoresListing(t, gatewayID)
		return listing["source"] == "data_plane" && storeStatus(listing, "corp-vault") == "ok"
	}, 30*time.Second, 500*time.Millisecond, "the data plane never reported its store to the admin")

	registriesURL := fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gatewayID)
	status, body := sendRequest(t, http.MethodPost, registriesURL, nil,
		dblessBackendPayload(uniqueName("be"), upstream.server.URL, "secret://corp-vault/prod/db#password"))
	require.Equal(t, http.StatusUnprocessableEntity, status, "a path outside allowed_paths must be refused: %v", body)
	assert.Equal(t, "secret_path_not_allowed", body["error"])
	status, body = sendRequest(t, http.MethodPost, registriesURL, nil,
		dblessBackendPayload(uniqueName("be"), upstream.server.URL, "secret://nope/ai-gateway/openai"))
	require.Equal(t, http.StatusUnprocessableEntity, status, "an unknown store must be refused: %v", body)
	assert.Equal(t, "unknown_secret_store", body["error"])

	ref := "secret://corp-vault/" + vaultTestPath + "#api_key"
	registryID := CreateRegistry(t, gatewayID, dblessBackendPayload(uniqueName("be"), upstream.server.URL, ref))
	status, body = sendRequest(t, http.MethodGet, fmt.Sprintf("%s/%s", registriesURL, registryID), nil, nil)
	require.Equal(t, http.StatusOK, status)
	raw, _ := json.Marshal(body)
	assert.Contains(t, string(raw), ref, "the admin returns the reference as written")
	assert.NotContains(t, string(raw), key1, "the admin never holds the value")

	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := chatCompletionsPath(t, coID)

	require.True(t, pollProxyServedAt(t, base, apiKey, path, "secret-stores-marker", 30*time.Second),
		"the data plane never served with the credential read from the vault")
	require.True(t, pollDBLessReady(base, 10*time.Second), "the readiness gate never opened")
	assert.Contains(t, upstream.keysSeen(), key1)

	t.Run("data-plane test reports the outcome, never the value", func(t *testing.T) {
		code, raw := postJSONStatus(t, base+"/__diagnostics/gateways/"+gatewayID+"/secret-stores/corp-vault/test",
			map[string]string{diagnosticsTokenHeader: mintDiagnosticsToken(t, gatewayID, "diagnostics")},
			map[string]any{"path": vaultTestPath, "field": "api_key"})
		require.Equal(t, http.StatusOK, code, "%s", raw)
		assert.Contains(t, string(raw), `"auth":"ok"`)
		assert.Contains(t, string(raw), `"read":"ok"`)
		assert.NotContains(t, string(raw), key1)

		code, raw = postJSONStatus(t, fmt.Sprintf("%s/v1/gateways/%s/secret-stores/corp-vault/test", AdminURL, gatewayID),
			map[string]string{"Authorization": "Bearer " + AdminToken}, map[string]any{"path": vaultTestPath})
		assert.Equal(t, http.StatusConflict, code, "%s", raw)
		assert.Contains(t, string(raw), "test_runs_on_data_plane")
	})

	t.Run("a rotated key is picked up on the upstream's 401", func(t *testing.T) {
		vault.rotate(key2)
		upstream.expect(key2)
		code, _, body := proxyPostAt(t, base, apiKey, path, chatRequest(false))
		require.Equal(t, http.StatusOK, code, "the request must be retried once with the rotated key: %s", body)
		seen := upstream.keysSeen()
		require.GreaterOrEqual(t, len(seen), 2)
		assert.Equal(t, []string{key1, key2}, seen[len(seen)-2:], "one 401 with the old key, then the new one")
	})

	t.Run("a vault outage does not stop serving", func(t *testing.T) {
		vault.setDown(true)
		defer vault.setDown(false)
		for range 3 {
			code, _, body := proxyPostAt(t, base, apiKey, path, chatRequest(false))
			require.Equal(t, http.StatusOK, code, "%s", body)
		}
		require.Eventually(t, func() bool {
			return storeStatus(secretStoresListing(t, gatewayID), "corp-vault") == "down"
		}, 15*time.Second, 500*time.Millisecond, "the outage never reached the admin listing")
	})

	t.Run("the pre-deploy scan finds the reference and prints no value", func(t *testing.T) {
		cmd := exec.Command(gatewayBinaryPath, "secret-refs-scan") //nolint:gosec // controlled binary path
		cmd.Env = buildCmdEnv("", "", "")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var exit *exec.ExitError
		require.True(t, errors.As(err, &exit), "the scan must exit non-zero: %v\n%s", err, stderr.String())
		assert.Equal(t, 3, exit.ExitCode(), "%s", stderr.String())
		assert.Contains(t, stdout.String(), registryID+"\t")
		assert.Contains(t, stdout.String(), "llm_target.auth.api_key.api_key\treference")
		assert.NotContains(t, stdout.String()+stderr.String(), key1)
		assert.NotContains(t, stdout.String()+stderr.String(), key2)
	})

	captured := logs.String()
	assert.NotContains(t, captured, key1, "the data plane must never log a resolved value")
	assert.NotContains(t, captured, key2, "the data plane must never log a resolved value")
}

// startRunPlane starts a self-hosted install, admin and proxy in one process,
// on its own ports and the suite's database, with a store file of its own.
func startRunPlane(t *testing.T, adminPort, proxyPort, grpcPort int, overrides []string) (adminURL, proxyURL string, logs *syncBuffer) {
	t.Helper()
	requireFreePorts([]int{adminPort, proxyPort, grpcPort})
	logs = &syncBuffer{}
	cmd := exec.Command(gatewayBinaryPath, "run") //nolint:gosec // controlled binary path
	cmd.Env = append(buildCmdEnv("", "", ""),
		fmt.Sprintf("SERVER_ADMIN_PORT=%d", adminPort),
		fmt.Sprintf("SERVER_PROXY_PORT=%d", proxyPort),
		fmt.Sprintf("CONFIG_SYNC_GRPC_LISTEN_ADDR=:%d", grpcPort),
	)
	cmd.Env = append(cmd.Env, overrides...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prefix := fmt.Sprintf("[RUN:%d] ", adminPort)
	cmd.Stdout = io.MultiWriter(&prefixWriter{prefix: prefix, w: os.Stdout}, logs)
	cmd.Stderr = io.MultiWriter(&prefixWriter{prefix: prefix + "ERR ", w: os.Stderr}, logs)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	})
	adminURL = fmt.Sprintf("http://localhost:%d", adminPort)
	proxyURL = fmt.Sprintf("http://localhost:%d", proxyPort)
	waitForDBLessLiveness(t, adminURL)
	waitForDBLessLiveness(t, proxyURL)
	return adminURL, proxyURL, logs
}

func TestSecretStoresExternalE2E(t *testing.T) {
	defer Track(t, "SecretStores")()

	apiKey := "sk-file-" + uuid.NewString()
	upstream := newKeyedUpstream(t, apiKey, "external-secret-marker")
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "secrets", "llm"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets", "llm", "openai"), []byte(apiKey), 0o600))
	storeFile := filepath.Join(dir, "secret-stores.yaml")
	require.NoError(t, os.WriteFile(storeFile, []byte(fmt.Sprintf(`version: 1
stores:
  - name: files
    type: file
    allowed_paths: ["llm/"]
    file:
      root: %s
`, filepath.Join(dir, "secrets"))), 0o600))

	base := GlobalConfig.Server.AdminPort + 200
	adminURL, proxyURL, logs := startRunPlane(t, base, base+1, base+3, []string{
		"SECRET_STORES_FILE=" + storeFile,
		"SECRET_STORES_GATEWAYS=all",
		"SECRET_STORES_PROBE_INTERVAL=1s",
	})

	admin := func(method, path string, body any) (int, map[string]any) {
		return sendRequest(t, method, adminURL+path, nil, body)
	}
	// The run plane shares the suite's database: the gateway, consumer and
	// key go through the suite's helpers, the reference through the admin
	// that loads the store file.
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("files-gw")})

	require.Eventually(t, func() bool {
		_, listing := admin(http.MethodGet, "/v1/gateways/"+gatewayID+"/secret-stores", nil)
		return listing["source"] == "control_plane" && storeStatus(listing, "files") == "ok"
	}, 20*time.Second, 500*time.Millisecond, "the admin never listed its own store as ok")

	code, raw := postJSONStatus(t, adminURL+"/v1/gateways/"+gatewayID+"/secret-stores/files/test",
		map[string]string{"Authorization": "Bearer " + AdminToken}, map[string]any{"path": "llm/openai"})
	require.Equal(t, http.StatusOK, code, "%s", raw)
	assert.Contains(t, string(raw), `"read":"ok"`)
	assert.NotContains(t, string(raw), apiKey)

	status, body := admin(http.MethodPost, "/v1/gateways/"+gatewayID+"/registries",
		dblessBackendPayload(uniqueName("be"), upstream.server.URL, "secret://files/llm/openai"))
	require.Equal(t, http.StatusCreated, status, "the admin validates the reference against its own catalog: %v", body)
	registryID, _ := body["id"].(string)

	status, body = admin(http.MethodPost, "/v1/gateways/"+gatewayID+"/registries/test-connection", map[string]any{"registry_id": registryID})
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, true, body["ok"], "test-connection resolves the reference: %v", body)

	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	consumerKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := chatCompletionsPath(t, coID)

	require.True(t, pollProxyServedAt(t, proxyURL, consumerKey, path, "external-secret-marker", 30*time.Second),
		"the self-hosted proxy never served with the credential read from the file store")
	assert.Contains(t, upstream.keysSeen(), apiKey)
	assert.NotContains(t, logs.String(), apiKey, "the run plane must never log a resolved value")
}
