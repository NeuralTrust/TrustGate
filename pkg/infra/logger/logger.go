package logger

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func NewLogger(serverType string) *logrus.Logger {
	logger := logrus.New()

	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime: "time",
			logrus.FieldKeyMsg:  "msg",
		},
	})

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "debug" {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	var logFile string
	if serverType == "admin" {
		logFile = "logs/admin.log"
	} else {
		logFile = "logs/proxy.log"
	}

	logFile = filepath.Clean(logFile)
	if !strings.HasPrefix(logFile, "logs/") {
		log.Fatalf("Invalid log file path: must be in logs directory")
	}

	if err := os.MkdirAll("logs", 0750); err != nil {
		log.Fatalf("Failed to create logs directory: %v", err)
	}

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()
	asyncWriter, err := NewAsyncFileWriter(logFile, 32*1024)
	if err != nil {
		log.Fatalf("Failed to initialize async log writer: %v", err)
	}

	logger.SetOutput(asyncWriter)

	asyncConsoleHook := NewConsoleHook()
	logger.AddHook(asyncConsoleHook)

	return logger
}
