package functional_test

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
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
	GlobalConfig *config.Config
	redisDB      *redis.Client
	proxyCmd     *exec.Cmd
	adminCmd     *exec.Cmd
	AdminUrl     = getEnv("ADMIN_URL", "")
	ProxyUrl     = getEnv("PROXY_URL", "")
	BaseDomain   = getEnv("BASE_DOMAIN", "")
	AdminToken   = getEnv("ADMIN_TOKEN", "")
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
	code := m.Run()
	teardownTestEnvironment()
	os.Exit(code)
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func setupTestEnvironment() {

	err := godotenv.Load("../../.env.functional")
	if err != nil {
		log.Println("no .env file found, using system environment variables")
	}

	if err := config.Load("../../config/"); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	GlobalConfig = config.GetConfig()

	killProcessesOnPorts([]int{8080, 8081})

	AdminUrl = getEnv("ADMIN_URL", "http://localhost:8080/api/v1")
	ProxyUrl = getEnv("PROXY_URL", "http://localhost:8081")
	BaseDomain = getEnv("BASE_DOMAIN", "example.com")

	jwtManager := jwt.NewJwtManager(&GlobalConfig.Server)
	tkn, err := jwtManager.CreateToken()
	if err != nil {
		log.Fatalf("failed to create token: %v", err)
	}
	AdminToken = tkn

	createTestDB(dbName)
	redisDB = redis.NewClient(&redis.Options{
		Addr: redisAddr,
		DB:   9,
	})

	// Get the current working directory and set it for the commands
	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get working directory: %v", err)
	}
	fmt.Printf("📁 Current working directory: %s\n", wd)

	// Create proxy command
	proxyCmd = exec.Command("go", "run", "../../cmd/gateway/main.go", "proxy")
	proxyCmd.Dir = wd
	proxyCmd.Env = append(os.Environ(), "ENV_FILE=../../.env.functional")
	proxyCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Create pipes to capture proxy server output (must be called before Start)
	proxyStdout, err := proxyCmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to create proxy stdout pipe: %v", err)
	}
	proxyStderr, err := proxyCmd.StderrPipe()
	if err != nil {
		log.Fatalf("Failed to create proxy stderr pipe: %v", err)
	}

	// Start goroutines to capture and log proxy server output
	go func() {
		scanner := bufio.NewScanner(proxyStdout)
		for scanner.Scan() {
			fmt.Printf("[PROXY STDOUT] %s\n", scanner.Text())
		}
	}()
	go func() {
		scanner := bufio.NewScanner(proxyStderr)
		for scanner.Scan() {
			fmt.Printf("[PROXY STDERR] %s\n", scanner.Text())
		}
	}()

	// Create admin command
	adminCmd = exec.Command("go", "run", "../../cmd/gateway/main.go", "admin")
	adminCmd.Dir = wd
	adminCmd.Env = append(os.Environ(), "ENV_FILE=../../.env.functional")
	adminCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Create pipes to capture admin server output (must be called before Start)
	adminStdout, err := adminCmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to create admin stdout pipe: %v", err)
	}
	adminStderr, err := adminCmd.StderrPipe()
	if err != nil {
		log.Fatalf("Failed to create admin stderr pipe: %v", err)
	}

	// Start goroutines to capture and log admin server output
	go func() {
		scanner := bufio.NewScanner(adminStdout)
		for scanner.Scan() {
			fmt.Printf("[ADMIN STDOUT] %s\n", scanner.Text())
		}
	}()
	go func() {
		scanner := bufio.NewScanner(adminStderr)
		for scanner.Scan() {
			fmt.Printf("[ADMIN STDERR] %s\n", scanner.Text())
		}
	}()

	fmt.Println("✨ Starting ProxyConfig Server:", proxyCmd.String())
	fmt.Printf("   Command: %s\n", proxyCmd.String())
	fmt.Printf("   Working directory: %s\n", proxyCmd.Dir)
	if err := proxyCmd.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
	fmt.Printf("   Proxy server started with PID: %d\n", proxyCmd.Process.Pid)

	time.Sleep(5 * time.Second)

	// Check if proxy process is still running
	if proxyCmd.Process != nil {
		if err := proxyCmd.Process.Signal(syscall.Signal(0)); err != nil {
			log.Printf("⚠ Warning: Proxy server process may have exited: %v", err)
		} else {
			fmt.Printf("✅ Proxy server process is still running (PID: %d)\n", proxyCmd.Process.Pid)
		}
	} else {
		log.Printf("❌ Proxy server process is nil")
	}

	fmt.Println("✨ Starting Admin Server:", adminCmd.String())
	fmt.Printf("   Command: %s\n", adminCmd.String())
	fmt.Printf("   Working directory: %s\n", adminCmd.Dir)
	if err := adminCmd.Start(); err != nil {
		log.Fatalf("Failed to start admin: %v", err)
	}
	fmt.Printf("   Admin server started with PID: %d\n", adminCmd.Process.Pid)

	time.Sleep(5 * time.Second)

	// Check if admin process is still running
	if adminCmd.Process != nil {
		if err := adminCmd.Process.Signal(syscall.Signal(0)); err != nil {
			log.Printf("⚠ Warning: Admin server process may have exited: %v", err)
		} else {
			fmt.Printf("✅ Admin server process is still running (PID: %d)\n", adminCmd.Process.Pid)
		}
	} else {
		log.Printf("❌ Admin server process is nil")
	}

	// Wait for servers to be ready
	waitForServerReady("http://localhost:8081/__/health", "proxy server")
	waitForServerReady("http://localhost:8080/version", "admin server")

	fmt.Println("🚀 Test Environment Ready")
}

func waitForServerReady(url, serverName string) {
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
			fmt.Printf("   Response status: %d\n", resp.StatusCode)
			_ = resp.Body.Close()
		} else if err != nil {
			fmt.Printf("   Connection error: %v\n", err)
		}

		if i == maxRetries-1 {
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
		log.Fatalf("Error creating databaase: %v", err)
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
