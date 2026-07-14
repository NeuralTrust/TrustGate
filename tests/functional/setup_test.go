//go:build functional

// Package functional_test boots the admin server as a real process
// against a dedicated Postgres database and exercises it through HTTP.
// Each test file in this package is a black-box smoke test of the
// run-281 admin CRUD surface; nothing here imports app/domain code.
package functional_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
)

var (
	GlobalConfig      *config.Config
	redisDB           *redis.Client
	adminCmd          *exec.Cmd
	proxyCmd          *exec.Cmd
	mcpCmd            *exec.Cmd
	gatewayBinaryPath string

	AdminURL   = getEnv("ADMIN_URL", "")
	ProxyURL   = getEnv("PROXY_URL", "")
	MCPURL     = getEnv("MCP_URL", "")
	BaseDomain = getEnv("BASE_DOMAIN", "")

	// AdminToken is a JWT signed with the same secret the admin server boots
	// with, so the suite can authenticate against the admin-plane auth middleware.
	AdminToken string
)

const (
	dbUser     = "postgres"
	dbPassword = "postgres"
	dbHost     = "localhost"
	dbPort     = "5432"
	dbName     = "trustgate_functional"
	redisAddr  = "localhost:6379"
	redisDBIdx = 9

	// serverConfigSyncGRPCPort is the loopback port the harness control plane
	// binds its config-sync gRPC listener on so the DB-less data plane can dial
	// it over plaintext (see dblessOverrides).
	serverConfigSyncGRPCPort = 8083
)

func TestMain(m *testing.M) {
	fmt.Println("Creating Test Environment...")
	setupTestEnvironment()

	GlobalReporter = NewTestReporter()

	code := m.Run()

	if GlobalReporter != nil {
		GlobalReporter.PrintReportWithExitCode(code)
	}

	teardownTestEnvironment()
	os.Exit(code)
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// buildCmdEnv returns the env the gateway binary will see, pinning
// ENV_FILE so it loads the same .env.functional as TestMain.
func buildCmdEnv(trustGuardBaseURL string) []string {
	env := os.Environ()
	env = append(env, "ENV_FILE=../../.env.functional")
	env = append(env, "AWS_ENDPOINT_URL_BEDROCK_RUNTIME="+bedrockGuardrailEndpoint)
	env = append(env, "TRUSTGUARD_CLIENT_ID="+trustGuardFunctionalClientID)
	env = append(env, "TRUSTGUARD_CLIENT_SECRET="+trustGuardFunctionalClientSecret)
	if trustGuardBaseURL != "" {
		env = append(env, "TRUSTGUARD_BASE_URL="+trustGuardBaseURL)
	}
	return env
}

func setupTestEnvironment() {
	if err := godotenv.Overload("../../.env.functional"); err != nil {
		log.Printf("no .env.functional found, relying on system env: %v", err)
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	GlobalConfig = cfg

	AdminURL = getEnv("ADMIN_URL", fmt.Sprintf("http://localhost:%d", cfg.Server.AdminPort))
	ProxyURL = getEnv("PROXY_URL", fmt.Sprintf("http://localhost:%d", cfg.Server.ProxyPort))
	MCPURL = getEnv("MCP_URL", fmt.Sprintf("http://localhost:%d", cfg.Server.MCPPort))
	BaseDomain = getEnv("BASE_DOMAIN", "example.com")

	token, err := jwt.NewJwtManager(&cfg.Server).CreateToken()
	if err != nil {
		log.Fatalf("failed to mint admin token: %v", err)
	}
	AdminToken = token

	killProcessesOnPorts([]int{cfg.Server.AdminPort, cfg.Server.ProxyPort, cfg.Server.MCPPort, serverConfigSyncGRPCPort})

	dropTestDB(dbName)
	createTestDB(dbName)

	redisDB = redis.NewClient(&redis.Options{Addr: redisAddr, DB: redisDBIdx})
	_ = redisDB.FlushDB(context.Background()).Err()

	_ = os.Setenv("CONFIG_SYNC_TOKEN", dblessConfigSyncToken)
	_ = os.Setenv("CONFIG_SYNC_RECOMPILE_DEBOUNCE", "500ms")
	_ = os.Setenv("CONFIG_SYNC_GRPC_LISTEN_ADDR", fmt.Sprintf(":%d", serverConfigSyncGRPCPort))

	trustGuardStubURL := StartTrustGuardFunctionalStub()
	cmdEnv := buildCmdEnv(trustGuardStubURL)
	gatewayBinaryPath = buildGatewayBinary(cmdEnv)

	// The admin plane runs the migrations on boot; wait for it to be ready before
	// starting the proxy so the two boots do not race on the (idempotent) schema.
	adminCmd = startServer("ADMIN", "admin", cmdEnv)
	waitForServerReady(fmt.Sprintf("%s/healthz", AdminURL), "admin server", cfg.Server.AdminPort)

	// The proxy plane serves the E2E forwarding tests; it shares the same DB and
	// Redis as the admin plane.
	proxyCmd = startServer("PROXY", "proxy", cmdEnv)
	waitForServerReady(fmt.Sprintf("%s/healthz", ProxyURL), "proxy server", cfg.Server.ProxyPort)

	mcpCmd = startServer("MCP", "mcp", cmdEnv)
	waitForServerReady(fmt.Sprintf("%s/healthz", MCPURL), "mcp server", cfg.Server.MCPPort)

	fmt.Println("Test Environment Ready")
}

func teardownTestEnvironment() {
	StopTrustGuardFunctionalStub()
	if mcpCmd != nil && mcpCmd.Process != nil {
		if err := syscall.Kill(-mcpCmd.Process.Pid, syscall.SIGKILL); err != nil {
			log.Printf("error killing mcp server: %v", err)
		}
	}
	if proxyCmd != nil && proxyCmd.Process != nil {
		if err := syscall.Kill(-proxyCmd.Process.Pid, syscall.SIGKILL); err != nil {
			log.Printf("error killing proxy server: %v", err)
		}
	}
	if adminCmd != nil && adminCmd.Process != nil {
		if err := syscall.Kill(-adminCmd.Process.Pid, syscall.SIGKILL); err != nil {
			log.Printf("error killing admin server: %v", err)
		}
	}
	if gatewayBinaryPath != "" {
		_ = os.RemoveAll(filepath.Dir(gatewayBinaryPath))
	}
	if redisDB != nil {
		_ = redisDB.FlushDB(context.Background()).Err()
		_ = redisDB.Close()
	}
	dropTestDB(dbName)
	fmt.Println("Test Environment Torn Down")
}

func buildGatewayBinary(env []string) string {
	tmpDir, err := os.MkdirTemp("", "trustgate-test-*")
	if err != nil {
		log.Fatalf("failed to create temp dir for gateway binary: %v", err)
	}
	binaryPath := filepath.Join(tmpDir, "trustgate")

	fmt.Println("Pre-building trustgate binary...")
	start := time.Now()
	cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/trustgate") //nolint:gosec // controlled paths
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to build trustgate binary: %v", err)
	}
	fmt.Printf("Built trustgate binary in %s\n", time.Since(start).Round(time.Millisecond))
	return binaryPath
}

type prefixWriter struct {
	prefix string
	w      io.Writer
	buf    []byte
}

func (pw *prefixWriter) Write(p []byte) (int, error) {
	pw.buf = append(pw.buf, p...)
	for {
		idx := bytes.IndexByte(pw.buf, '\n')
		if idx < 0 {
			break
		}
		_, _ = fmt.Fprintf(pw.w, "%s%s\n", pw.prefix, string(pw.buf[:idx]))
		pw.buf = pw.buf[idx+1:]
	}
	return len(p), nil
}

func (pw *prefixWriter) Flush() {
	if len(pw.buf) > 0 {
		_, _ = fmt.Fprintf(pw.w, "%s%s\n", pw.prefix, string(pw.buf))
		pw.buf = nil
	}
}

func startServer(label, mode string, env []string) *exec.Cmd {
	cmd := exec.Command(gatewayBinaryPath, mode) //nolint:gosec // controlled binary path
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout := &prefixWriter{prefix: fmt.Sprintf("[%s] ", label), w: os.Stdout}
	stderr := &prefixWriter{prefix: fmt.Sprintf("[%s ERR] ", label), w: os.Stderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	fmt.Printf("Starting %s server: %s %s\n", label, gatewayBinaryPath, mode)
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start %s: %v", label, err)
	}
	fmt.Printf("  %s pid=%d\n", label, cmd.Process.Pid)

	exitCh := make(chan struct{}, 1)
	go func() {
		if err := cmd.Wait(); err != nil {
			fmt.Printf("[%s EXIT] %v\n", label, err)
		}
		stdout.Flush()
		stderr.Flush()
		close(exitCh)
	}()

	select {
	case <-exitCh:
		log.Fatalf("%s server exited immediately; check logs above", label)
	case <-time.After(3 * time.Second):
	}
	return cmd
}

func waitForServerReady(url, name string, port int) {
	const maxRetries = 30
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(url) //nolint:gosec // controlled URL
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				fmt.Printf("%s ready\n", name)
				return
			}
		}
		if i == maxRetries-1 {
			checkPortListening(port, name)
			log.Fatalf("%s never became ready after %ds: %v", name, maxRetries, err)
		}
		time.Sleep(time.Second)
	}
}

// pgxAdminConn opens a one-shot connection to the default "postgres"
// database; required because you cannot CREATE/DROP the database you
// are currently connected to.
func pgxAdminConn(ctx context.Context) (*pgx.Conn, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=disable",
		dbUser, dbPassword, dbHost, dbPort)
	return pgx.Connect(ctx, dsn)
}

func createTestDB(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgxAdminConn(ctx)
	if err != nil {
		log.Fatalf("cannot connect to postgres: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s;", name)); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return
		}
		log.Fatalf("error creating database %s: %v", name, err)
	}
	fmt.Printf("Database %s created\n", name)
}

func dropTestDB(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgxAdminConn(ctx)
	if err != nil {
		log.Printf("cannot connect to postgres for drop: %v", err)
		return
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE);", name)); err != nil {
		log.Printf("error dropping database %s: %v", name, err)
		return
	}
	fmt.Printf("Database %s dropped\n", name)
}

func checkPortListening(port int, name string) {
	cmd := exec.Command("lsof", "-ti", fmt.Sprintf(":%d", port)) //nolint:gosec // hardcoded callsite
	out, err := cmd.Output()
	if err != nil {
		fmt.Printf("port %d is NOT listening for %s\n", port, name)
		return
	}
	if pids := strings.TrimSpace(string(out)); pids != "" {
		fmt.Printf("port %d listening pids=%s for %s\n", port, pids, name)
	}
}

func killProcessesOnPorts(ports []int) {
	for _, port := range ports {
		cmd := exec.Command("lsof", "-ti", fmt.Sprintf(":%d", port)) //nolint:gosec // hardcoded callsite
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		for _, pidStr := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			pidStr = strings.TrimSpace(pidStr)
			if pidStr == "" {
				continue
			}
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				continue
			}
			fmt.Printf("Killing pid=%d on port %d\n", pid, port)
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	}
}
