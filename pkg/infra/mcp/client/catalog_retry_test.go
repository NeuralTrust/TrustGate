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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCachedCatalogFailuresDoNotRepeatDiscovery(t *testing.T) {
	for _, mode := range []string{"cursor", "response", "items"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int64
			server := sdk.NewServer(&sdk.Implementation{Name: "upstream", Version: "1"}, nil)
			handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Body == nil {
					handler.ServeHTTP(w, r)
					return
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(data))
				var request struct {
					Method string
					ID     json.RawMessage
				}
				if len(data) > 0 {
					if err := json.Unmarshal(data, &request); err != nil {
						t.Error(err)
						return
					}
				}
				if request.Method != "tools/list" {
					handler.ServeHTTP(w, r)
					return
				}
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "cursor":
					if _, err := fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[],"nextCursor":"same"}}`, request.ID); err != nil {
						return
					}
				case "response":
					if _, err := fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[],"padding":"%s"}}`, request.ID, strings.Repeat("x", maxResponseBytes)); err != nil {
						return
					}
				case "items":
					items := make([]map[string]any, maxCatalogItems+1)
					for i := range items {
						items[i] = map[string]any{"name": "tool", "inputSchema": map[string]any{"type": "object"}}
					}
					if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"tools": items}}); err != nil {
						t.Error(err)
					}
				}
			}))
			defer srv.Close()
			d := NewCachedDialer(New(), slog.New(slog.DiscardHandler)).(*cachedDialer)
			defer func() {
				for _, entry := range d.entries {
					entry.session.Close(context.Background())
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			up, err := d.Connect(ctx, appmcp.Target{URL: srv.URL, PinKey: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = up.ListTools(ctx); err == nil {
				t.Fatal("invalid catalog accepted")
			}
			want := int64(1)
			if mode == "cursor" {
				want = 2
			}
			if got := calls.Load(); got != want {
				t.Fatalf("upstream requests=%d, want %d (no discovery retry)", got, want)
			}
		})
	}
}
