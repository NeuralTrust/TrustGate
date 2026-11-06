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

package grpc

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) entries(t *testing.T, msg string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if entry["msg"] == msg {
			out = append(out, entry)
		}
	}
	return out
}

func (b *logBuffer) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

func capturePullLogs(client *Client) *logBuffer {
	logs := &logBuffer{}
	client.logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logs
}

func onlyEntry(t *testing.T, entries []map[string]any) map[string]any {
	t.Helper()
	if len(entries) != 1 {
		t.Fatalf("want exactly one entry, got %d: %v", len(entries), entries)
	}
	return entries[0]
}

func countStatus(entries []map[string]any, status, level string) int {
	n := 0
	for _, entry := range entries {
		if entry["status"] == status && entry["level"] == level {
			n++
		}
	}
	return n
}

func TestPullLogReadsLikeDockerPull(t *testing.T) {
	parts := frags(30, "pull")
	source := newLayeredFake(parts)
	client := layeredClient(t, source)
	logs := capturePullLogs(client)

	if _, _, _, err := client.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	fragments := logs.entries(t, "pull fragment")
	if got := countStatus(fragments, "Pull complete", "INFO"); got != maxFragmentLogLines {
		t.Fatalf("a cold pull of 30 fragments logs %d per-fragment lines, want the cap of %d", got, maxFragmentLogLines)
	}
	summary := onlyEntry(t, logs.entries(t, "pull complete"))
	if summary["mode"] != "layered" || summary["status"] != pullStatusDownloaded || summary["pulled"] != float64(30) ||
		summary["already_exists"] != float64(0) || summary["fragments"] != float64(30) || summary["restarts"] != float64(0) {
		t.Fatalf("cold pull summary = %v", summary)
	}

	changed := append([][]byte{[]byte("pull-fragment-0000-changed")}, parts[1:]...)
	source.publish(changed)
	logs.reset()
	raw, version, _, err := client.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	fragments = logs.entries(t, "pull fragment")
	if got := countStatus(fragments, "Pull complete", "INFO"); got != 1 {
		t.Fatalf("one changed fragment logs %d pulled lines, want 1", got)
	}
	if got := countStatus(fragments, "Already exists", "DEBUG"); got != 29 {
		t.Fatalf("29 cached fragments log %d already-exists lines at DEBUG, want 29", got)
	}
	if got := countStatus(fragments, "Already exists", "INFO"); got != 0 {
		t.Fatalf("already-exists lines must stay at DEBUG, got %d at INFO", got)
	}
	pulled := countStatus(fragments, "Pull complete", "INFO")
	for _, entry := range fragments {
		if entry["status"] == "Pull complete" && len(entry["fragment"].(string)) != 12 {
			t.Fatalf("fragment must be the 12-character short digest, got %v", entry["fragment"])
		}
	}
	summary = onlyEntry(t, logs.entries(t, "pull complete"))
	if summary["version"] != version || summary["pulled"] != float64(pulled) || summary["already_exists"] != float64(29) ||
		summary["pulled_bytes"] != float64(len(changed[0])) || summary["total_bytes"] != float64(len(raw)) {
		t.Fatalf("warm pull summary = %v", summary)
	}
	if _, ok := summary["duration"]; !ok {
		t.Fatalf("pull summary must carry the duration: %v", summary)
	}

	logs.reset()
	if _, _, notModified, err := client.Fetch(context.Background(), version); err != nil || !notModified {
		t.Fatalf("fetch with the current etag: notModified=%v err=%v", notModified, err)
	}
	summary = onlyEntry(t, logs.entries(t, "pull complete"))
	if summary["status"] != pullStatusUpToDate || summary["version"] != version || summary["mode"] != "layered" {
		t.Fatalf("up-to-date summary = %v", summary)
	}
	if got := len(logs.entries(t, "pull fragment")); got != 0 {
		t.Fatalf("an up-to-date pull logs no fragments, got %d", got)
	}
}

func TestPullLogNamesTheFallbackToTheSingleBlob(t *testing.T) {
	source := newLayeredFake(frags(3, "fallback"))
	source.layered = false
	client := layeredClient(t, source)
	logs := capturePullLogs(client)

	raw, version, _, err := client.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	summary := onlyEntry(t, logs.entries(t, "pull complete"))
	if summary["mode"] != "full" || summary["fallback_reason"] != fallbackUnimplemented || summary["version"] != version ||
		summary["pulled_bytes"] != float64(len(raw)) || summary["total_bytes"] != float64(len(raw)) {
		t.Fatalf("fallback summary = %v", summary)
	}
}

func TestPullLogOfThePlainSingleBlobPathHasNoFallbackReason(t *testing.T) {
	source := &fakeSource{}
	source.set([]byte("single-blob"), "v-blob")
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), source, discardLogger(), nil))
	client := dialClient(t, lis, "dp-full")
	logs := capturePullLogs(client)

	if _, _, _, err := client.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	summary := onlyEntry(t, logs.entries(t, "pull complete"))
	if summary["mode"] != "full" || summary["status"] != pullStatusDownloaded || summary["pulled_bytes"] != float64(len("single-blob")) {
		t.Fatalf("single-blob summary = %v", summary)
	}
	if _, ok := summary["fallback_reason"]; ok {
		t.Fatalf("a plain single-blob pull has no fallback reason: %v", summary)
	}
	logs.reset()
	if _, _, notModified, err := client.Fetch(context.Background(), "v-blob"); err != nil || !notModified {
		t.Fatalf("fetch with the current etag: notModified=%v err=%v", notModified, err)
	}
	summary = onlyEntry(t, logs.entries(t, "pull complete"))
	if summary["status"] != pullStatusUpToDate || summary["mode"] != "full" {
		t.Fatalf("single-blob up-to-date summary = %v", summary)
	}
}
