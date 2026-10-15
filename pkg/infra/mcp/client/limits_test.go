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

package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	mcpclient "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/client"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func interceptUpstream(t *testing.T, method string, respond func(http.ResponseWriter, *http.Request, json.RawMessage)) *mcpclient.Session {
	t.Helper()
	srv := newUpstream(t, func(s *sdk.Server) {
		addEchoTool(s)
		s.AddResource(&sdk.Resource{Name: "r", URI: "file:///r"}, func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{}, nil
		})
		s.AddPrompt(&sdk.Prompt{Name: "p"}, func(context.Context, *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
			return &sdk.GetPromptResult{}, nil
		})
	}, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, id := readRequestEnvelope(t, r)
			if got == method {
				respond(w, r, id)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	return connect(t, appmcp.Target{URL: srv.URL})
}

func TestResponseSizeLimits(t *testing.T) {
	for _, kind := range []string{"json", "sse", "sse-bare-cr"} {
		t.Run(kind, func(t *testing.T) {
			sess := interceptUpstream(t, "tools/call", func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
				if kind == "json" {
					w.Header().Set("Content-Type", "application/json")
				} else {
					w.Header().Set("Content-Type", "text/event-stream")
				}
				w.(http.Flusher).Flush()
				if kind == "sse" {
					if _, err := fmt.Fprint(w, "data: "); err != nil {
						return
					}
				}
				payload := strings.Repeat("x", 8<<20)
				if kind == "sse-bare-cr" {
					payload = strings.Repeat("\r", 8<<20)
				}
				if _, err := fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"%s"}]}}`, id, payload); err != nil {
					return
				}
				if kind != "json" {
					if _, err := fmt.Fprint(w, "\n\n"); err != nil {
						return
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, err := sess.CallTool(ctx, "echo", nil)
			if !errors.Is(err, mcpclient.ErrResponseTooLarge) {
				t.Fatalf("error = %v, want ErrResponseTooLarge", err)
			}
		})
	}
}

func TestSSEAllowsManyBoundedEvents(t *testing.T) {
	sess := interceptUpstream(t, "tools/call", func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
		w.Header().Set("Content-Type", "text/event-stream")
		line := ":" + strings.Repeat("x", 1<<20) + "\r\n\r\n"
		for range 10 {
			if _, err := fmt.Fprint(w, line); err != nil {
				return
			}
		}
		if _, err := fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[]}}\n\n", id); err != nil {
			return
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := sess.CallTool(ctx, "echo", nil); err != nil {
		t.Fatalf("bounded SSE events: %v", err)
	}
}

func TestDiscoveryPaginationLimits(t *testing.T) {
	for _, method := range []string{"tools/list", "resources/list", "resources/templates/list", "prompts/list"} {
		for _, mode := range []string{"valid", "repeated", "pages", "items", "bytes"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				var pages atomic.Int64
				field := map[string]string{"tools/list": "tools", "resources/list": "resources", "resources/templates/list": "resourceTemplates", "prompts/list": "prompts"}[method]
				sess := interceptUpstream(t, method, func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
					page := pages.Add(1)
					cursor := "same"
					items := []map[string]any{{"name": "entry", "uri": "file:///r", "uriTemplate": "file:///{x}", "inputSchema": map[string]any{"type": "object"}}}
					switch mode {
					case "valid":
						if page == 2 {
							cursor = ""
						}
					case "pages":
						cursor = fmt.Sprint(page)
						items = nil
					case "items":
						cursor = ""
						for len(items) <= 10000 {
							items = append(items, items[0])
						}
					case "bytes":
						cursor = fmt.Sprint(page)
						items[0]["description"] = strings.Repeat("x", 6<<20)
					}
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{field: items, "nextCursor": cursor}}); err != nil {
						return
					}
				})
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				var err error
				var count int
				switch method {
				case "tools/list":
					v, e := sess.ListTools(ctx)
					count, err = len(v), e
				case "resources/list":
					v, e := sess.ListResources(ctx)
					count, err = len(v), e
				case "resources/templates/list":
					v, e := sess.ListResourceTemplates(ctx)
					count, err = len(v), e
				case "prompts/list":
					v, e := sess.ListPrompts(ctx)
					count, err = len(v), e
				}
				switch mode {
				case "valid":
					if err != nil || count != 2 || pages.Load() != 2 {
						t.Fatalf("count=%d pages=%d err=%v", count, pages.Load(), err)
					}
				case "repeated":
					if err == nil || !strings.Contains(err.Error(), "repeated") || pages.Load() != 2 {
						t.Fatalf("pages=%d err=%v", pages.Load(), err)
					}
				default:
					if !errors.Is(err, mcpclient.ErrCatalogTooLarge) || count != 0 {
						t.Fatalf("count=%d pages=%d err=%v", count, pages.Load(), err)
					}
				}
			})
		}
	}
}

func TestCloseReturnsAtCallerDeadlineDuringDelete(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	srv := newUpstream(t, nil, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
				}
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	sess := connect(t, appmcp.Target{URL: srv.URL})
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { sess.Close(ctx); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("teardown did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close ignored its deadline")
	}
	if err := sess.Ping(context.Background()); err == nil {
		t.Fatal("closed session accepted ping")
	}
}

func TestConcurrentCloseAndCalls(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, addEchoTool, nil)
	sess := connect(t, appmcp.Target{URL: srv.URL})
	start := make(chan struct{})
	var group sync.WaitGroup
	for i := range 24 {
		group.Go(func() {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if i%3 == 0 {
				sess.Close(ctx)
				return
			}
			_, _ = sess.CallTool(ctx, "echo", nil)
		})
	}
	close(start)
	group.Wait()
	if err := sess.Ping(context.Background()); err == nil {
		t.Fatal("session reopened after concurrent close")
	}
}

func TestConnectRejectsOversizedSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := fmt.Fprint(w, "data: "+strings.Repeat("x", (8<<20)+1)+"\n\n"); err != nil {
			return
		}
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := mcpclient.New().Connect(ctx, appmcp.Target{URL: srv.URL})
	if !errors.Is(err, mcpclient.ErrResponseTooLarge) {
		t.Fatalf("connect error=%v, want ErrResponseTooLarge", err)
	}
}

func TestErrorResponseCannotBypassLimitWithSSEContentType(t *testing.T) {
	sess := interceptUpstream(t, "tools/call", func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusForbidden)
		line := ":" + strings.Repeat("x", 1<<20) + "\n\n"
		for range 10 {
			if _, err := fmt.Fprint(w, line); err != nil {
				return
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := sess.CallTool(ctx, "echo", nil)
	if !errors.Is(err, mcpclient.ErrResponseTooLarge) {
		t.Fatalf("error=%v, want ErrResponseTooLarge", err)
	}
}
