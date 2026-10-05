//go:build functional

package functional_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminLKGPortOffset keeps the throwaway admin planes off the suite's own
// admin and config-sync ports.
const adminLKGPortOffset = 200

type adminPlane struct {
	cmd  *exec.Cmd
	logs *syncBuffer
	grpc int
}

func (a *adminPlane) stop() {
	if a.cmd != nil && a.cmd.Process != nil {
		_ = syscall.Kill(-a.cmd.Process.Pid, syscall.SIGKILL)
		_, _ = a.cmd.Process.Wait()
	}
}

// startThrowawayAdmin runs an extra admin plane on its own ports against the
// suite's database, so the suite's shared admin keeps serving the other tests.
func startThrowawayAdmin(t *testing.T, lkgEnabled bool) *adminPlane {
	t.Helper()
	httpPort := GlobalConfig.Server.AdminPort + adminLKGPortOffset
	grpcPort := serverConfigSyncGRPCPort + adminLKGPortOffset
	requireFreePorts([]int{httpPort, grpcPort})

	logs := &syncBuffer{}
	cmd := exec.Command(gatewayBinaryPath, "admin") //nolint:gosec // controlled binary path
	cmd.Env = append(os.Environ(),
		"SERVER_ADMIN_PORT="+strconv.Itoa(httpPort),
		fmt.Sprintf("CONFIG_SYNC_GRPC_LISTEN_ADDR=:%d", grpcPort),
		"CONFIG_SYNC_ADMIN_LKG_ENABLED="+strconv.FormatBool(lkgEnabled),
		// The suite runs at LOG_LEVEL=WARN (.env.functional.example), which hides
		// the INFO line these tests wait on. Later entries win, so this one does.
		"LOG_LEVEL=INFO",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prefix := fmt.Sprintf("[ADMIN-LKG:%d] ", httpPort)
	cmd.Stdout = io.MultiWriter(&prefixWriter{prefix: prefix, w: os.Stdout}, logs)
	cmd.Stderr = io.MultiWriter(&prefixWriter{prefix: prefix + "ERR ", w: os.Stderr}, logs)
	require.NoError(t, cmd.Start(), "start throwaway admin")

	plane := &adminPlane{cmd: cmd, logs: logs, grpc: grpcPort}
	t.Cleanup(plane.stop)
	waitForDBLessLiveness(t, fmt.Sprintf("http://localhost:%d", httpPort))
	return plane
}

func waitForLog(t *testing.T, logs *syncBuffer, needle string, timeout time.Duration) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), needle) },
		timeout, 200*time.Millisecond, "log never contained %q:\n%s", needle, logs.String())
}

func connectFunctionalDB(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		GlobalConfig.Database.User, GlobalConfig.Database.Password,
		GlobalConfig.Database.Host, GlobalConfig.Database.Port, dbName)
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// corruptEveryPolicy makes every policy row undecodable, which trips the
// mass-skip breaker in the compiler, and restores the rows when the test ends so
// the rest of the suite is unaffected. At least two rows must exist for the
// breaker to trip, so the caller seeds them first.
func corruptEveryPolicy(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	backup := "lkg_e2e_policy_backup_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	_, err := conn.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s AS SELECT id, settings FROM policies`, backup))
	require.NoError(t, err)
	t.Cleanup(func() {
		if _, err := conn.Exec(context.Background(),
			fmt.Sprintf(`UPDATE policies p SET settings = b.settings FROM %s b WHERE p.id = b.id`, backup)); err != nil {
			t.Errorf("restoring policies after the test failed, the suite database is left corrupted: %v", err)
		}
		if _, err := conn.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s`, backup)); err != nil {
			t.Errorf("dropping the policy backup table failed: %v", err)
		}
	})
	tag, err := conn.Exec(ctx, `UPDATE policies SET settings = '[1,2]'::jsonb`)
	require.NoError(t, err)
	require.GreaterOrEqual(t, tag.RowsAffected(), int64(2), "the breaker needs at least two unreadable policies")
}

type lkgScenario struct {
	apiKey, path string
}

func seedLKGScenario(t *testing.T) lkgScenario {
	t.Helper()
	upstream := newJSONUpstream(t, "admin-lkg-marker")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("lkg-gw")})
	registryID := CreateRegistry(t, gatewayID, dblessBackendPayload(uniqueName("be"), upstream.URL(), "sk-lkg-"+uuid.NewString()))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	// Three policies so the breaker has a table to trip on.
	for i := 0; i < 3; i++ {
		CreatePolicy(t, gatewayID, validPolicyPayload(uniqueName("lkg-policy")))
	}
	return lkgScenario{apiKey: apiKey, path: chatCompletionsPath(t, coID)}
}

func startLKGDataPlane(t *testing.T, admin *adminPlane, name string) (string, *syncBuffer) {
	t.Helper()
	port := GlobalConfig.Server.ProxyPort + 110
	// A fresh, empty LKG path: this pod has never seen a snapshot, like a pod
	// created by a rollout or a scale-up.
	lkgPath := filepath.Join(t.TempDir(), "snapshot.lkg")
	overrides := append(dblessOverrides(lkgPath, dblessConfigSyncToken, uniqueName(name), port),
		"CONFIG_SYNC_GRPC_ENDPOINT="+fmt.Sprintf("localhost:%d", admin.grpc))
	return startDBLessProxyPlane(t, port, overrides)
}

// TestAdminLKG_RestartedAdminWhoseCompileFailsStillServesNewPods is the whole
// RUN-1662 path: the admin compiles and persists, restarts into a database where
// the mass-skip breaker fails every compile, and a data-plane pod with no local
// LKG still becomes ready and serves a key created before the breakage.
func TestAdminLKG_RestartedAdminWhoseCompileFailsStillServesNewPods(t *testing.T) {
	defer Track(t, "AdminLKG")()
	sc := seedLKGScenario(t)
	conn := connectFunctionalDB(t)

	// The suite's own admin persists to this table too. Clear it first, so a row
	// can only come from the throwaway admin started below.
	_, err := conn.Exec(context.Background(), `DELETE FROM config_snapshot_lkg`)
	require.NoError(t, err)
	startedAt := time.Now()

	healthy := startThrowawayAdmin(t, true)
	waitForLog(t, healthy.logs, "published config snapshot", 30*time.Second)
	require.Eventually(t, func() bool {
		var n int
		return conn.QueryRow(context.Background(),
			`SELECT count(*) FROM config_snapshot_lkg WHERE scope = '' AND compiled_at >= $1`, startedAt).Scan(&n) == nil && n == 1
	}, 15*time.Second, 200*time.Millisecond, "the throwaway admin never persisted the global snapshot")
	healthy.stop()

	corruptEveryPolicy(t, conn)

	broken := startThrowawayAdmin(t, true)
	waitForLog(t, broken.logs, "serving persisted config snapshot until a compile succeeds", 30*time.Second)
	waitForLog(t, broken.logs, "too many unreadable policies", 30*time.Second)

	base, _ := startLKGDataPlane(t, broken, "lkg-pod")
	require.True(t, pollDBLessReady(base, 30*time.Second),
		"a pod with no local LKG never became ready while the admin served its persisted snapshot")
	require.True(t, pollProxyServedAt(t, base, sc.apiKey, sc.path, "admin-lkg-marker", 30*time.Second),
		"the pod never served the key that existed when the snapshot was persisted")
}

// TestAdminLKG_FeatureOffLeavesNewPodUnready proves the test above depends on the
// feature: with it off, the same broken restart leaves a new pod without a
// snapshot, which is the gap RUN-1662 describes.
func TestAdminLKG_FeatureOffLeavesNewPodUnready(t *testing.T) {
	defer Track(t, "AdminLKG")()
	_ = seedLKGScenario(t)
	conn := connectFunctionalDB(t)

	healthy := startThrowawayAdmin(t, false)
	waitForLog(t, healthy.logs, "published config snapshot", 30*time.Second)
	healthy.stop()

	corruptEveryPolicy(t, conn)

	broken := startThrowawayAdmin(t, false)
	waitForLog(t, broken.logs, "too many unreadable policies", 30*time.Second)
	assert.NotContains(t, broken.logs.String(), "serving persisted config snapshot")

	base, _ := startLKGDataPlane(t, broken, "lkg-off-pod")
	assert.False(t, pollDBLessReady(base, 10*time.Second),
		"with the feature off a pod must stay unready while the admin cannot compile")
	status, body := sendRequest(t, http.MethodGet, base+"/readyz", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, status, "readyz: %v", body)
}
