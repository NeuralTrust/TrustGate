package logger

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
)

// Logger struct wrapping slog.Logger
type Logger struct {
	logger *slog.Logger
}

// NewLogger initializes a new structured logger
func NewLogger(serverType string, logLevel string) *Logger {
	logFile := "proxy.log"
	if serverType == "admin" {
		logFile = "admin.log"
	}

	level := getLogLevel(logLevel)
	logPath := clearOrCreateLogFile(logFile)

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		slog.Error("failed to open log file", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Create console and file handlers
	consoleHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level, AddSource: true})
	fileHandler := slog.NewJSONHandler(file, &slog.HandlerOptions{Level: level, AddSource: true})

	// Multi-handler
	h := &multiHandler{handlers: []slog.Handler{consoleHandler, fileHandler}}
	l := slog.New(h)

	// Set global logger
	slog.SetDefault(l)
	slog.SetLogLoggerLevel(level)

	l.Info("logging initialized", slog.String("log_file", logPath))

	return &Logger{logger: l}
}

func (l *Logger) InfoContext(ctx context.Context, msg string, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	l.logger.InfoContext(ctx, msg, convertedArgs...)
}

func (l *Logger) WarnContext(ctx context.Context, msg string, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	l.logger.WarnContext(ctx, msg, convertedArgs...)
}

func (l *Logger) ErrorContext(ctx context.Context, msg string, err error, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	convertedArgs = append(convertedArgs, slog.String("error", err.Error()))
	l.logger.ErrorContext(ctx, msg, convertedArgs...)
}

func (l *Logger) DebugContext(ctx context.Context, msg string, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	l.logger.DebugContext(ctx, msg, convertedArgs...)
}

func (l *Logger) FatalContext(ctx context.Context, msg string, err error, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	convertedArgs = append(convertedArgs, slog.String("error", err.Error()))

	l.logger.ErrorContext(ctx, msg, convertedArgs...)
	os.Exit(1)
}

func (l *Logger) Info(msg string, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	l.logger.Info(msg, convertedArgs...)
}

func (l *Logger) Warn(msg string, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	l.logger.Warn(msg, convertedArgs...)
}

func (l *Logger) Error(msg string, err error, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	convertedArgs = append(convertedArgs, slog.String("error", err.Error()))
	l.logger.Error(msg, convertedArgs...)
}

func (l *Logger) Debug(msg string, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	l.logger.Debug(msg, convertedArgs...)
}

func (l *Logger) Fatal(msg string, err error, args ...slog.Attr) {
	convertedArgs := convertAttrsToAny(args)
	convertedArgs = append(convertedArgs, slog.String("error", err.Error()))
	l.logger.Error(msg, convertedArgs...)
	os.Exit(1)
}

// Helper Functions

func convertAttrsToAny(attrs []slog.Attr) []any {
	converted := make([]any, len(attrs))
	for i, attr := range attrs {
		converted[i] = attr
	}
	return converted
}

func getLogLevel(level string) slog.Level {
	switch level {
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelDebug
	}
}

func getProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		slog.Error("failed to get project root", slog.String("error", err.Error()))
		os.Exit(1)
	}
	return dir
}

func setUpLogDir() string {
	logDir := filepath.Join(getProjectRoot(), "logs")
	if err := os.MkdirAll(logDir, 0750); err != nil {
		slog.Error("failed to create logs directory", slog.String("error", err.Error()))
		os.Exit(1)
	}
	return logDir
}

func clearOrCreateLogFile(logFile string) string {
	logPath := filepath.Join(setUpLogDir(), logFile)
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		slog.Error("failed to open log file", slog.String("error", err.Error()))
		os.Exit(1)
	}
	_ = file.Close()
	return logPath
}

type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range m.handlers {
		if err := handler.Handle(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range m.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		newHandlers[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: newHandlers}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	newHandlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		newHandlers[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: newHandlers}
}
