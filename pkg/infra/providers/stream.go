package providers

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StreamSSE reads an SSE stream line-by-line and sends each line (pass-through)
// to out. The handler is responsible for writing each line + "\n" to the
// response body. Empty lines (SSE event separators) are forwarded so the
// downstream client receives a byte-accurate SSE stream.
//
// When a "data: [DONE]" line is encountered (OpenAI/Azure convention) it is
// forwarded and the function returns immediately. For providers that do not
// use [DONE] (Anthropic, Gemini) the loop ends naturally when the reader is
// exhausted.
//
// If TG_SAVE_STREAM_RAW is set, the raw upstream stream (before any adaptation)
// is written to streams/raw_<timestamp>.sse for debugging (e.g. to confirm whether
// the upstream already returns empty or the problem is in response conversion).
//
// This function is safe to call from a goroutine — it must receive a context
// that does NOT depend on Fiber's request lifecycle (e.g. context.Background()).
func StreamSSE(ctx context.Context, r io.Reader, out chan<- []byte) error {
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 512*1024)
	sc.Buffer(buf, 2*1024*1024)

	var rawFile *os.File
	if os.Getenv("TG_SAVE_STREAM_RAW") == "true" {
		dir := "streams"
		_ = os.MkdirAll(dir, 0750)
		ts := time.Now().Format("20060102-150405")
		path := filepath.Join(dir, "raw_"+ts+".sse")
		f, err := os.Create(path) // #nosec G304 -- path is from constant dir and timestamp, not user input
		if err == nil {
			rawFile = f
			defer func() { _ = rawFile.Close() }()
		}
	}

	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Copy: the Scanner reuses its internal buffer.
		line := append([]byte(nil), sc.Bytes()...)

		if rawFile != nil {
			_, _ = rawFile.Write(line)
			_, _ = rawFile.Write([]byte("\n"))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- line:
		}

		// OpenAI/Azure end-of-stream marker.
		if bytes.HasPrefix(line, []byte("data:")) {
			payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if bytes.Equal(payload, []byte("[DONE]")) {
				return nil
			}
		}
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, io.EOF) ||
			strings.Contains(strings.ToLower(err.Error()), "use of closed network connection") ||
			strings.Contains(strings.ToLower(err.Error()), "connection reset by peer") {
			return nil
		}
		return fmt.Errorf("sse scanner error: %w", err)
	}
	return nil
}
