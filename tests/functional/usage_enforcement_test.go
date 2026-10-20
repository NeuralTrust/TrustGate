//go:build functional

package functional_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	usagev1 "github.com/NeuralTrust/TrustGate/pkg/infra/usagesync/proto/usage/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// usageAdminPortOffset keeps the usage-enforcing admin off the suite's admin
// and off the LKG tests' throwaway admin.
const usageAdminPortOffset = 300

const usageStatesKey = "gt:usage:states"

// startUsageAdmin runs an extra admin plane with Usage System enforcement on,
// against the suite's database and Redis, and returns its config-sync port.
func startUsageAdmin(t *testing.T, extra ...string) int {
	t.Helper()
	httpPort := GlobalConfig.Server.AdminPort + usageAdminPortOffset
	grpcPort := serverConfigSyncGRPCPort + usageAdminPortOffset
	requireFreePorts([]int{httpPort, grpcPort})

	logs := &syncBuffer{}
	cmd := exec.Command(gatewayBinaryPath, "admin") //nolint:gosec // controlled binary path
	cmd.Env = append(os.Environ(),
		"SERVER_ADMIN_PORT="+strconv.Itoa(httpPort),
		fmt.Sprintf("CONFIG_SYNC_GRPC_LISTEN_ADDR=:%d", grpcPort),
		"USAGE_SYSTEM_ENABLED=true",
	)
	cmd.Env = append(cmd.Env, extra...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prefix := fmt.Sprintf("[ADMIN-USAGE:%d] ", httpPort)
	cmd.Stdout = io.MultiWriter(&prefixWriter{prefix: prefix, w: os.Stdout}, logs)
	cmd.Stderr = io.MultiWriter(&prefixWriter{prefix: prefix + "ERR ", w: os.Stderr}, logs)
	require.NoError(t, cmd.Start(), "start usage admin")
	plane := &adminPlane{cmd: cmd, logs: logs, grpc: grpcPort}
	t.Cleanup(plane.stop)

	base := fmt.Sprintf("http://localhost:%d", httpPort)
	waitForDBLessLiveness(t, base)
	require.True(t, pollDBLessReady(base, 30*time.Second), "usage admin never became ready")
	_, ready := sendRequest(t, http.MethodGet, base+"/readyz", nil, nil)
	deps, _ := ready["dependencies"].(map[string]any)
	require.Equal(t, "ok", deps["usage_list"], "admin with usage enforcement must report its usage list: %v", ready)
	return grpcPort
}

type usageTenant struct {
	apiKey string
	path   string
	up     *fakeUpstream
}

func usageTenantGateway(t *testing.T, tenant, marker string) usageTenant {
	t.Helper()
	up := newJSONUpstream(t, marker)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("usage-gw"), "tenant_id": tenant})
	registryID := CreateRegistry(t, gatewayID, dblessBackendPayload(uniqueName("be"), up.URL(), "sk-usage-"+uniqueName("k")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	return usageTenant{apiKey: createAndAttachAPIKey(t, gatewayID, coID), path: chatCompletionsPath(t, coID), up: up}
}

// TestUsageEnforcement_BlocksExhaustedTenantThroughTheDataPlane seeds an
// exhausted tenant in the control plane's usage cache, boots an admin plane
// that enforces usage and a DB-less proxy plane fed by it, and checks that the
// exhausted tenant is refused with 402 before reaching its upstream while
// another tenant is served.
func TestUsageEnforcement_BlocksExhaustedTenantThroughTheDataPlane(t *testing.T) {
	defer Track(t, "UsageEnforcement")()

	exhaustedTenant := uniqueName("usage-broke")
	healthyTenant := uniqueName("usage-fine")
	broke := usageTenantGateway(t, exhaustedTenant, "usage-broke-marker")
	fine := usageTenantGateway(t, healthyTenant, "usage-fine-marker")

	require.NoError(t, redisDB.HSet(context.Background(), usageStatesKey, exhaustedTenant, "10|exhausted|wallet_empty").Err())
	t.Cleanup(func() { _ = redisDB.HDel(context.Background(), usageStatesKey, exhaustedTenant).Err() })

	grpcPort := startUsageAdmin(t)

	port := GlobalConfig.Server.ProxyPort + 130
	lkgPath := filepath.Join(t.TempDir(), "snapshot.lkg")
	overrides := append(dblessOverrides(lkgPath, dblessConfigSyncToken, uniqueName("usage-dp"), port),
		fmt.Sprintf("CONFIG_SYNC_GRPC_ENDPOINT=localhost:%d", grpcPort))
	base, _ := startDBLessProxyPlane(t, port, overrides)
	require.True(t, pollDBLessReady(base, 30*time.Second), "data plane never became ready")
	_, ready := sendRequest(t, http.MethodGet, base+"/readyz", nil, nil)
	deps, _ := ready["dependencies"].(map[string]any)
	assert.Equal(t, "ok", deps["usage_list"], "data plane must report its usage list: %v", ready)

	require.True(t, pollProxyServedAt(t, base, fine.apiKey, fine.path, "usage-fine-marker", 30*time.Second),
		"the healthy tenant must be served")

	require.True(t, pollProxyStatusAt(t, base, broke.apiKey, broke.path, chatRequest(false), http.StatusPaymentRequired, 30*time.Second),
		"the exhausted tenant must be refused with 402")
	status, _, body := proxyPostAt(t, base, broke.apiKey, broke.path, chatRequest(false))
	require.Equal(t, http.StatusPaymentRequired, status)
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope), string(body))
	assert.Equal(t, "insufficient_funds", envelope.Error.Code)
	assert.Zero(t, broke.up.Hits(), "a refused request must never reach the upstream")

	brokeMCP := CreateGateway(t, map[string]any{"slug": uniqueName("usage-mcp-broke"), "tenant_id": exhaustedTenant})
	fineMCP := CreateGateway(t, map[string]any{"slug": uniqueName("usage-mcp-fine"), "tenant_id": healthyTenant})
	mcpKey := func(gatewayID, tenant string) string {
		token := userToken(t, tenant, uniqueName("usage-user"))
		status, issued := llmKeyRequest(t, http.MethodPost, gatewayID, token, "", llmKeyExpiry(llmKeyDay))
		require.Equal(t, http.StatusCreated, status, "body=%v", issued)
		return fmt.Sprint(issued["api_key"])
	}
	brokeKey, fineKey := mcpKey(brokeMCP, exhaustedTenant), mcpKey(fineMCP, healthyTenant)
	mcpBase, _ := startDBLessMCPPlane(t, GlobalConfig.Server.MCPPort+130, uniqueName("usage-mcp"),
		fmt.Sprintf("CONFIG_SYNC_GRPC_ENDPOINT=localhost:%d", grpcPort))

	require.Eventually(t, func() bool {
		status, _ := storeMCPAt(t, mcpBase, fineMCP, fineKey, "tools/list", map[string]any{})
		return status == http.StatusOK
	}, 30*time.Second, 300*time.Millisecond, "the healthy tenant must be served on MCP")

	var refused map[string]any
	require.Eventually(t, func() bool {
		var status int
		status, refused = storeMCPAt(t, mcpBase, brokeMCP, brokeKey, "tools/list", map[string]any{})
		return status == http.StatusPaymentRequired
	}, 30*time.Second, 300*time.Millisecond, "the exhausted tenant must be refused on MCP with HTTP 402")
	rpcErr, _ := refused["error"].(map[string]any)
	require.NotNil(t, rpcErr, "refusal must be a JSON-RPC error: %v", refused)
	data, _ := rpcErr["data"].(map[string]any)
	assert.Equal(t, "insufficient_funds", data["code"], "refusal=%v", refused)
}

// fakeUsageSystem is an in-test UsageSync server: it answers every stream with
// the current snapshot and pushes each change to the open streams.
type fakeUsageSystem struct {
	usagev1.UnimplementedUsageSyncServiceServer
	mu      sync.Mutex
	states  map[string]*usagev1.UsageState
	asOf    int64
	streams map[usagev1.UsageSyncService_SyncServer]chan *usagev1.UsageState
}

func startFakeUsageSystem(t *testing.T) (*fakeUsageSystem, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	fake := &fakeUsageSystem{
		states:  map[string]*usagev1.UsageState{},
		streams: map[usagev1.UsageSyncService_SyncServer]chan *usagev1.UsageState{},
	}
	srv := grpc.NewServer()
	usagev1.RegisterUsageSyncServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return fake, lis.Addr().String()
}

func (f *fakeUsageSystem) Sync(stream usagev1.UsageSyncService_SyncServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	changes := make(chan *usagev1.UsageState, 16)
	f.mu.Lock()
	snapshot := &usagev1.Snapshot{AsOfVersion: f.asOf}
	for _, st := range f.states {
		if st.GetStatus() == usagev1.UsageStatus_USAGE_STATUS_EXHAUSTED {
			snapshot.Exhausted = append(snapshot.Exhausted, st)
		}
	}
	f.streams[stream] = changes
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.streams, stream)
		f.mu.Unlock()
	}()
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				return
			}
		}
	}()
	if err := stream.Send(&usagev1.SyncResponse{Message: &usagev1.SyncResponse_Snapshot{Snapshot: snapshot}}); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case st := <-changes:
			if err := stream.Send(&usagev1.SyncResponse{Message: &usagev1.SyncResponse_Change{Change: st}}); err != nil {
				return err
			}
		}
	}
}

func (f *fakeUsageSystem) set(tenant string, exhausted bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asOf++
	st := &usagev1.UsageState{TenantId: tenant, Status: usagev1.UsageStatus_USAGE_STATUS_HEALTHY, Version: f.asOf}
	if exhausted {
		st.Status = usagev1.UsageStatus_USAGE_STATUS_EXHAUSTED
		st.Reason = usagev1.ExhaustionReason_EXHAUSTION_REASON_FREE_LIMIT_REACHED
	}
	f.states[tenant] = st
	for _, ch := range f.streams {
		ch <- st
	}
}

// TestUsageEnforcement_FollowsUsageSystemWithoutRestart drives the states from
// a UsageSync server: a tenant is blocked once Usage System exhausts it and
// served again once Usage System clears it, with no restart of any plane.
func TestUsageEnforcement_FollowsUsageSystemWithoutRestart(t *testing.T) {
	defer Track(t, "UsageEnforcement")()

	tenant := uniqueName("usage-live")
	gw := usageTenantGateway(t, tenant, "usage-live-marker")
	fake, addr := startFakeUsageSystem(t)

	grpcPort := startUsageAdmin(t, "USAGE_SYSTEM_GRPC_ADDR="+addr, "USAGE_SYSTEM_GRPC_INSECURE=true")
	port := GlobalConfig.Server.ProxyPort + 131
	overrides := append(dblessOverrides(filepath.Join(t.TempDir(), "snapshot.lkg"), dblessConfigSyncToken, uniqueName("usage-live-dp"), port),
		fmt.Sprintf("CONFIG_SYNC_GRPC_ENDPOINT=localhost:%d", grpcPort))
	base, _ := startDBLessProxyPlane(t, port, overrides)
	require.True(t, pollDBLessReady(base, 30*time.Second), "data plane never became ready")
	require.True(t, pollProxyServedAt(t, base, gw.apiKey, gw.path, "usage-live-marker", 30*time.Second), "tenant must be served before any block")

	fake.set(tenant, true)
	require.True(t, pollProxyStatusAt(t, base, gw.apiKey, gw.path, chatRequest(false), http.StatusPaymentRequired, 30*time.Second),
		"the tenant must be blocked once Usage System exhausts it")
	status, _, body := proxyPostAt(t, base, gw.apiKey, gw.path, chatRequest(false))
	require.Equal(t, http.StatusPaymentRequired, status)
	assert.Contains(t, string(body), "plan_limit")

	fake.set(tenant, false)
	require.True(t, pollProxyServedAt(t, base, gw.apiKey, gw.path, "usage-live-marker", 30*time.Second),
		"the tenant must be served again once Usage System clears it, without a restart")
}
