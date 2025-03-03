package functional_test

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

var (
	serverURL string
	redisDB   *redis.Client
	proxyCmd  *exec.Cmd
	adminCmd  *exec.Cmd
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

func setupTestEnvironment() {
	createTestDB(dbName)

	redisDB = redis.NewClient(&redis.Options{
		Addr: redisAddr,
		DB:   9,
	})

	proxyCmd = exec.Command("go", "run", "../../cmd/gateway/main.go", "proxy")
	proxyCmd.Env = append(os.Environ(), "ENV_FILE=../../.env.functional")
	proxyCmd.Stdout = os.Stdout
	proxyCmd.Stderr = os.Stderr
	proxyCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	adminCmd = exec.Command("go", "run", "../../cmd/gateway/main.go", "admin")
	adminCmd.Env = append(os.Environ(), "ENV_FILE=../../.env.functional")
	adminCmd.Stdout = os.Stdout
	adminCmd.Stderr = os.Stderr
	adminCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	fmt.Println("✨ Starting Proxy Server:", adminCmd.String())
	if err := proxyCmd.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	fmt.Println("✨ Starting Admin Server:", adminCmd.String())
	if err := adminCmd.Start(); err != nil {
		log.Fatalf("Failed to start admin: %v", err)
	}

	fmt.Println("🚀 Test Environment Ready")
}

func createTestDB(name string) {
	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=%s port=%s user=%s password=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword,
	))
	if err != nil {
		log.Fatalf("Cannot connect to PostgreSQL: %v", err)
	}
	defer db.Close()

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
		syscall.Kill(-proxyCmd.Process.Pid, syscall.SIGKILL)
	}
	if adminCmd != nil && adminCmd.Process != nil {
		syscall.Kill(-adminCmd.Process.Pid, syscall.SIGKILL)
	}
	fmt.Printf("🗑 Servers Stopped\n")
	defer redisDB.Close()
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
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("DROP DATABASE %s;", name))
	if err != nil {
		log.Printf("error removing database: %v", err)
	}
	fmt.Printf("🗑 Database %s removed\n", name)
}
