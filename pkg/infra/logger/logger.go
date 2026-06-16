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
	"strings"
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

type AsyncHandler struct {
	handler slog.Handler
	ch      chan logRecord
	done    chan struct{}
}

type logRecord struct {
	ctx    context.Context
	record slog.Record
	result chan error
}

func NewAsyncHandler(handler slog.Handler, bufferSize int) *AsyncHandler {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	ah := &AsyncHandler{
		handler: handler,
		ch:      make(chan logRecord, bufferSize),
		done:    make(chan struct{}),
	}
	go ah.worker()
	return ah
}

func (h *AsyncHandler) worker() {
	for {
		select {
		case record := <-h.ch:
			err := h.handler.Handle(record.ctx, record.record)
			record.result <- err
		case <-h.done:
			return
		}
	}
}

func (h *AsyncHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *AsyncHandler) Handle(ctx context.Context, r slog.Record) error {
	result := make(chan error, 1)
	select {
	case h.ch <- logRecord{ctx: ctx, record: r, result: result}:
		return <-result
	default:
		return h.handler.Handle(ctx, r)
	}
}

func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return NewAsyncHandler(h.handler.WithAttrs(attrs), cap(h.ch))
}

func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	return NewAsyncHandler(h.handler.WithGroup(name), cap(h.ch))
}

func (h *AsyncHandler) Close() {
	close(h.done)
}

type ColoredHandler struct {
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
	return NewLoggerWithFormat(level, LogFormatJSON)
}

func NewLoggerWithFormat(level slog.Level, format LogFormat) *slog.Logger {
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
	asyncConsoleHandler := NewAsyncHandler(consoleHandler, 1000)

	if !fileLogEnabled() {
		return slog.New(asyncConsoleHandler)
	}

	fileHandler, err := createFileHandler(handlerOpts)
	if err != nil {
		slog.Warn("file log sink unavailable, falling back to console-only", slog.String("error", err.Error()))
		return slog.New(asyncConsoleHandler)
	}

	multiHandler := NewMultiHandler(asyncConsoleHandler, fileHandler)
	return slog.New(multiHandler)
}

// fileLogEnabled gates the on-disk var/log.log sink. Containers should keep this
// off (stdout JSON only); enable locally with LOG_FILE_ENABLED=true.
func fileLogEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_FILE_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
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
	sourceFilterHandler := NewSourceFilterHandler(jsonHandler)
	asyncFileHandler := NewAsyncHandler(sourceFilterHandler, 1000)
	return asyncFileHandler, nil
}
