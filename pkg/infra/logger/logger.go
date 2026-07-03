// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

type MultiHandler struct {
	handlers []slog.Handler
}

func NewMultiHandler(handlers ...slog.Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

func (h *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		if err := handler.Handle(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (h *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		newHandlers[i] = handler.WithAttrs(attrs)
	}
	return NewMultiHandler(newHandlers...)
}

func (h *MultiHandler) WithGroup(name string) slog.Handler {
	newHandlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		newHandlers[i] = handler.WithGroup(name)
	}
	return NewMultiHandler(newHandlers...)
}

type SourceFilterHandler struct {
	handler slog.Handler
}

func NewSourceFilterHandler(handler slog.Handler) *SourceFilterHandler {
	return &SourceFilterHandler{handler: handler}
}

func (h *SourceFilterHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *SourceFilterHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level < slog.LevelWarn {
		newRecord := slog.Record{
			Time:    r.Time,
			Level:   r.Level,
			Message: r.Message,
		}
		r.Attrs(func(attr slog.Attr) bool {
			if attr.Key != "source" {
				newRecord.AddAttrs(attr)
			}
			return true
		})
		return h.handler.Handle(ctx, newRecord)
	}
	return h.handler.Handle(ctx, r)
}

func (h *SourceFilterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return NewSourceFilterHandler(h.handler.WithAttrs(attrs))
}

func (h *SourceFilterHandler) WithGroup(name string) slog.Handler {
	return NewSourceFilterHandler(h.handler.WithGroup(name))
}

type ColoredHandler struct {
	mu     sync.Mutex
	writer io.Writer
	level  slog.Level
}

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[37m"
)

func NewColoredHandler(writer io.Writer, level slog.Level) *ColoredHandler {
	return &ColoredHandler{writer: writer, level: level}
}

func (h *ColoredHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *ColoredHandler) Handle(_ context.Context, r slog.Record) error {
	var color string
	switch r.Level {
	case slog.LevelDebug:
		color = colorBlue
	case slog.LevelInfo:
		color = colorGreen
	case slog.LevelWarn:
		color = colorYellow
	case slog.LevelError:
		color = colorRed
	default:
		color = colorGray
	}
	timeStamp := r.Time.Format("15:04:05")
	message := fmt.Sprintf("%s%s%s | %s\n", color, timeStamp, colorReset, r.Message)
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.writer.Write([]byte(message))
	return err
}

func (h *ColoredHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

func (h *ColoredHandler) WithGroup(_ string) slog.Handler { return h }

type LogFormat string

const (
	LogFormatJSON    LogFormat = "json"
	LogFormatText    LogFormat = "text"
	LogFormatColored LogFormat = "colored"
)

func NewLogger(level slog.Level) *slog.Logger {
	return NewLoggerWithFormat(level, LogFormatJSON, false)
}

func NewLoggerWithFormat(level slog.Level, format LogFormat, fileEnabled bool) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}

	var consoleBaseHandler slog.Handler
	switch format {
	case LogFormatText:
		consoleBaseHandler = slog.NewTextHandler(os.Stdout, handlerOpts)
	case LogFormatColored:
		consoleBaseHandler = NewColoredHandler(os.Stdout, level)
	default:
		consoleBaseHandler = slog.NewJSONHandler(os.Stdout, handlerOpts)
	}

	consoleHandler := NewSourceFilterHandler(consoleBaseHandler)

	if !fileEnabled {
		return slog.New(consoleHandler)
	}

	fileHandler, err := createFileHandler(handlerOpts)
	if err != nil {
		slog.Warn("file log sink unavailable, falling back to console-only", slog.String("error", err.Error()))
		return slog.New(consoleHandler)
	}

	multiHandler := NewMultiHandler(consoleHandler, fileHandler)
	return slog.New(multiHandler)
}

func createFileHandler(opts *slog.HandlerOptions) (slog.Handler, error) {
	if err := os.MkdirAll("var", 0750); err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(filepath.Join("var", "log.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	jsonHandler := slog.NewJSONHandler(logFile, opts)
	return NewSourceFilterHandler(jsonHandler), nil
}
