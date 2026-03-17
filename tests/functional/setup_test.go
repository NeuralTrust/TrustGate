package functional_test

import (
	"bytes"
	"context"
	"database/sql"
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
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var (
	GlobalConfig      *config.Config
	redisDB           *redis.Client
	proxyCmd          *exec.Cmd
	adminCmd          *exec.Cmd
	gatewayBinaryPath string
	AdminUrl          = getEnv("ADMIN_URL", "")
	ProxyUrl          = getEnv("PROXY_URL", "")
	BaseDomain        = getEnv("BASE_DOMAIN", "")
	AdminToken        = getEnv("ADMIN_TOKEN", "")
)

const (
	dbUser     = "postgres"
	dbPassword = "postgres"
	dbHost     = "localhost"
	dbPort     = "5432"
	dbName     = "functional_test"
	redisAddr  = "localhost:6379"
)

func TestMain(m *testing.M) {
	fmt.Println("🔨 Creating Test Environment...")
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

func buildCmdEnv() []string {
	env := os.Environ()
	env = append(env,
		"ENV_FILE=../../.env.functional",
		"TLS_CERTS_BASE_PATH=/tmp/certs",
	)
	return env
}

func setupTestEnvironment() {
	err := godotenv.Load("../../.env.functional")
	if err != nil {
		log.Println("no .env file found, using system environment variables")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	GlobalConfig = cfg

	AdminUrl = getEnv("ADMIN_URL", "http://localhost:8080/api/v1")
	ProxyUrl = getEnv("PROXY_URL", "http://localhost:8081")
	BaseDomain = getEnv("BASE_DOMAIN", "example.com")

	_ = os.Setenv("TLS_CERTS_BASE_PATH", "/tmp/certs")

	jwtManager := jwt.NewJwtManager(&GlobalConfig.Server)
	tkn, err := jwtManager.CreateToken()
	if err != nil {
		log.Fatalf("failed to create token: %v", err)
	}
	AdminToken = tkn

	killProcessesOnPorts([]int{8080, 8081})

	createTestDB(dbName)
	redisDB = redis.NewClient(&redis.Options{
		Addr: redisAddr,
		DB:   9,
	})

	cmdEnv := buildCmdEnv()
	gatewayBinaryPath = buildGatewayBinary(cmdEnv)

	proxyCmd = startServer("PROXY", "proxy", cmdEnv)
	time.Sleep(3 * time.Second)
	adminCmd = startServer("ADMIN", "admin", cmdEnv)

	waitForServerReady("http://localhost:8081/__/health", "proxy server", 8081)
	waitForServerReady("http://localhost:8080/version", "admin server", 8080)

	fmt.Println("🚀 Test Environment Ready")
}

func buildGatewayBinary(env []string) string {
	tmpDir, err := os.MkdirTemp("", "gateway-test-*")
	if err != nil {
		log.Fatalf("Failed to create temp dir for gateway binary: %v", err)
	}
	binaryPath := filepath.Join(tmpDir, "gateway")

	fmt.Println("🔨 Pre-building gateway binary...")
	start := time.Now()
	cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/gateway") //nolint:gosec // paths are controlled in test environment
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatalf("❌ Failed to build gateway binary: %v", err)
	}
	fmt.Printf("✅ Gateway binary built in %s\n", time.Since(start).Round(time.Millisecond))
	return binaryPath
}

type prefixWriter struct {
	prefix string
	w      io.Writer
	buf    []byte
}

func (pw *prefixWriter) Write(p []byte) (n int, err error) {
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
	cmd := exec.Command(gatewayBinaryPath, mode) //nolint:gosec // binary path is controlled in test environment
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutWriter := &prefixWriter{prefix: fmt.Sprintf("[%s] ", label), w: os.Stdout}
	stderrWriter := &prefixWriter{prefix: fmt.Sprintf("[%s ERR] ", label), w: os.Stderr}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	fmt.Printf("✨ Starting %s Server: %s %s\n", label, gatewayBinaryPath, mode)
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start %s: %v", label, err)
	}
	fmt.Printf("   %s server started with PID: %d\n", label, cmd.Process.Pid)

	exitChan := make(chan struct{}, 1)
	go func() {
		if err := cmd.Wait(); err != nil {
			fmt.Printf("[%s EXIT] Process exited with error: %v\n", label, err)
		} else {
			fmt.Printf("[%s EXIT] Process exited successfully\n", label)
		}
		stdoutWriter.Flush()
		stderrWriter.Flush()
		if state := cmd.ProcessState; state != nil {
			fmt.Printf("[%s EXIT] Exit code: %d\n", label, state.ExitCode())
		}
		close(exitChan)
	}()

	select {
	case <-exitChan:
		log.Fatalf("❌ %s server exited immediately! Check [%s] logs above for errors.", label, label)
	case <-time.After(5 * time.Second):
		fmt.Printf("✅ %s server still running after 5 seconds\n", label)
	}

	return cmd
}

func waitForServerReady(url, serverName string, port int) {
	maxRetries := 30
	retryInterval := time.Second

	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(url) //nolint:gosec // URL is controlled in test environment
		if err == nil && resp.StatusCode < 500 {
			_ = resp.Body.Close()
			fmt.Printf("✅ %s is ready\n", serverName)
			return
		}
		if resp != nil {
			fmt.Printf("   %s response status: %d\n", serverName, resp.StatusCode)
			_ = resp.Body.Close()
		} else if err != nil {
			fmt.Printf("   %s connection error: %v\n", serverName, err)
		}

		if i == maxRetries-1 {
			checkPortListening(port, serverName)
			log.Fatalf("❌ %s failed to become ready after %d seconds. Last error: %v", serverName, maxRetries, err)
		}

		fmt.Printf("⏳ Waiting for %s to be ready... (attempt %d/%d)\n", serverName, i+1, maxRetries)
		time.Sleep(retryInterval)
	}
}

func createTestDB(name string) {
	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=%s port=%s user=%s password=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword,
	))
	if err != nil {
		log.Fatalf("Cannot connect to PostgreSQL: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s;", name))
	if err != nil {
		if err.Error() == "pq: database \"functional_test\" already exists" {
			return
		}
		log.Fatalf("Error creating database: %v", err)
	}
	fmt.Printf("✅ Database %s created\n", name)
}

func teardownTestEnvironment() {
	if proxyCmd != nil && proxyCmd.Process != nil {
		err := syscall.Kill(-proxyCmd.Process.Pid, syscall.SIGKILL)
		if err != nil {
			log.Printf("error killing proxy server: %v", err)
		}
	}
	if adminCmd != nil && adminCmd.Process != nil {
		err := syscall.Kill(-adminCmd.Process.Pid, syscall.SIGKILL)
		if err != nil {
			log.Printf("error killing admin server: %v", err)
		}
	}
	fmt.Printf("🗑 Servers Stopped\n")
	if gatewayBinaryPath != "" {
		_ = os.RemoveAll(filepath.Dir(gatewayBinaryPath))
		fmt.Println("🗑 Gateway binary removed")
	}
	defer func() { _ = redisDB.Close() }()
	dropTestDB(dbName)
	redisDB.FlushDB(context.Background())
	fmt.Printf("🗑 Redis flushed\n")
}

func dropTestDB(name string) {
	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=%s port=%s user=%s password=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword,
	))
	if err != nil {
		log.Printf("cannot connect to postgre to remove db %v", err)
		return
	}
	defer func() { _ = db.Close() }()

	_, err = db.Exec(fmt.Sprintf("DROP DATABASE %s;", name))
	if err != nil {
		log.Printf("error removing database: %v", err)
	}
	fmt.Printf("🗑 Database %s removed\n", name)
}

func checkPortListening(port int, serverName string) {
	cmd := exec.Command("lsof", "-ti", fmt.Sprintf(":%d", port)) //nolint:gosec // port is controlled from hardcoded list
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("⚠ Port %d is NOT listening (no process found) for %s\n", port, serverName)
		return
	}
	pidLines := strings.TrimSpace(string(output))
	if pidLines == "" {
		fmt.Printf("⚠ Port %d is NOT listening (no process found) for %s\n", port, serverName)
		return
	}
	for _, pidStr := range strings.Split(pidLines, "\n") {
		pidStr = strings.TrimSpace(pidStr)
		if pidStr != "" {
			fmt.Printf("✅ Port %d is listening (PID: %s) for %s\n", port, pidStr, serverName)
		}
	}
}

func killProcessesOnPorts(ports []int) {
	for _, port := range ports {
		fmt.Printf("🔍 Checking for processes on port %d...\n", port)

		cmd := exec.Command("lsof", "-ti", fmt.Sprintf(":%d", port)) //nolint:gosec // port is controlled from hardcoded list
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		pidLines := strings.TrimSpace(string(output))
		if pidLines == "" {
			continue
		}

		pids := strings.Split(pidLines, "\n")
		for _, pidStr := range pids {
			pidStr = strings.TrimSpace(pidStr)
			if pidStr == "" {
				continue
			}

			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				log.Printf("invalid PID: %s", pidStr)
				continue
			}

			fmt.Printf("🔪 Killing process %d on port %d\n", pid, port)
			process, err := os.FindProcess(pid)
			if err != nil {
				log.Printf("failed to find process %d: %v", pid, err)
				continue
			}

			err = process.Kill()
			if err != nil {
				log.Printf("failed to kill process %d: %v", pid, err)
			} else {
				fmt.Printf("✅ Process %d killed successfully\n", pid)
			}
		}
	}
}
