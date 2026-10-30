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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const mockCompletion = `{"id":"chatcmpl-bench","object":"chat.completion","created":1760000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"The quick brown fox jumps over the lazy dog. This is a canned completion served by the benchmark upstream."},"logprobs":null,"finish_reason":"stop"}],"usage":{"prompt_tokens":42,"completion_tokens":24,"total_tokens":66}}`

func runMock(args []string) error {
	fs := flag.NewFlagSet("mock", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:9999", "listen address")
	chunks := fs.Int("stream-chunks", 20, "delta chunks per streamed completion")
	delay := fs.Duration("delay", 0, "artificial upstream latency added before answering")
	_ = fs.Parse(args)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/logs") || strings.HasPrefix(r.URL.Path, "/v1/traces") || strings.HasPrefix(r.URL.Path, "/v1/metrics") {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/x-protobuf")
			w.WriteHeader(http.StatusOK)
			return
		}
		var req struct {
			Stream bool `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if *delay > 0 {
			time.Sleep(*delay)
		}
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"gpt-4o-mini","object":"model"}]}`)
			return
		}
		if req.Stream {
			writeMockStream(w, *chunks)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, mockCompletion)
	})

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Printf("mock upstream listening on http://%s\n", *addr)
	return srv.ListenAndServe()
}

func writeMockStream(w http.ResponseWriter, chunks int) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)
	for i := 0; i < chunks; i++ {
		_, _ = fmt.Fprintf(w,
			"data: {\"id\":\"chatcmpl-bench\",\"object\":\"chat.completion.chunk\",\"created\":1760000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"token%d \"},\"finish_reason\":null}]}\n\n", i)
		if flusher != nil {
			flusher.Flush()
		}
	}
	_, _ = fmt.Fprintf(w,
		"data: {\"id\":\"chatcmpl-bench\",\"object\":\"chat.completion.chunk\",\"created\":1760000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":%d,\"total_tokens\":%d}}\n\n", chunks, 42+chunks)
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}
