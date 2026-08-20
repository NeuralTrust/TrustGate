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

package mcp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	mcpclient "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/client"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type upstreamIntegrationServer struct {
	server        *httptest.Server
	events        chan string
	listens       atomic.Int32
	canceled      chan struct{}
	cancelOnce    sync.Once
	supportsTools bool
	listenFailure string
}

func newUpstreamIntegrationServer(t *testing.T, supportsTools bool) *upstreamIntegrationServer {
	t.Helper()
	upstream := &upstreamIntegrationServer{
		events:        make(chan string, 2),
		canceled:      make(chan struct{}),
		supportsTools: supportsTools,
	}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Mcp-Method") {
		case "server/discover":
			var request struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      request.ID,
				"result": map[string]any{
					"resultType":        "complete",
					"supportedVersions": []string{"2026-07-28"},
					"capabilities": map[string]any{
						"subscriptions": map[string]any{"listen": true},
						"tools":         map[string]any{"listChanged": upstream.supportsTools},
						"prompts":       map[string]any{"listChanged": false},
						"resources":     map[string]any{"listChanged": false},
					},
				},
			})
		case appmcp.MethodSubscriptionsListen:
			upstream.listens.Add(1)
			if upstream.listenFailure != "" {
				http.Error(w, upstream.listenFailure, http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			writeUpstreamIntegrationFrame(w, `{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"notifications":{"toolsListChanged":true,"promptsListChanged":false,"resourcesListChanged":false}}}`)
			flusher.Flush()
			for {
				select {
				case event := <-upstream.events:
					writeUpstreamIntegrationFrame(w, event)
					flusher.Flush()
				case <-r.Context().Done():
					upstream.cancelOnce.Do(func() { close(upstream.canceled) })
					return
				}
			}
		default:
			http.Error(w, "unexpected MCP method", http.StatusBadRequest)
		}
	}))
	t.Cleanup(upstream.server.Close)
	return upstream
}

func writeUpstreamIntegrationFrame(w io.Writer, payload string) {
	_, _ = io.WriteString(w, "event: message\ndata: "+payload+"\n\n")
}

type upstreamIntegrationFinder struct {
	data *appconsumer.Data
}

func (f upstreamIntegrationFinder) FindByGateway(
	context.Context,
	ids.GatewayID,
) (*appconsumer.Data, error) {
	return f.data, nil
}

type upstreamIntegrationScoper struct {
	mu      sync.RWMutex
	revoked map[string]bool
}

func (s *upstreamIntegrationScoper) Scope(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	_ *appconsumer.Data,
) (*appconsumer.RoutableConsumer, error) {
	principal := identity.PrincipalFromContext(ctx)
	s.mu.RLock()
	revoked := principal != nil && s.revoked[principal.Subject]
	s.mu.RUnlock()
	if revoked {
		return nil, appmcp.ErrNoRoleAccess
	}
	return rc, nil
}

func (s *upstreamIntegrationScoper) revoke(subject string) {
	s.mu.Lock()
	s.revoked[subject] = true
	s.mu.Unlock()
}

type upstreamIntegrationHarness struct {
	url         string
	app         *fiber.App
	multiplexer *appmcp.SubscriptionMultiplexer
	registry    *appmcp.SubscriptionRegistry
	served      chan error
	closeOnce   sync.Once
	closeErr    error
}

func newUpstreamIntegrationHarness(
	t *testing.T,
	upstream *upstreamIntegrationServer,
	scoper *upstreamIntegrationScoper,
) *upstreamIntegrationHarness {
	return newUpstreamIntegrationHarnessWithCaps(
		t,
		upstream,
		scoper,
		4,
		4,
		4,
		false,
	)
}

func newUpstreamIntegrationHarnessWithCaps(
	t *testing.T,
	upstream *upstreamIntegrationServer,
	scoper *upstreamIntegrationScoper,
	maxListeners int,
	maxPerOrigin int,
	maxStreams int,
	perPrincipalSource bool,
) *upstreamIntegrationHarness {
	t.Helper()
	gatewayID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	registry, err := registrydomain.NewMCPRegistry(
		gatewayID,
		"upstream",
		"",
		&registrydomain.MCPTarget{
			URL:          upstream.server.URL,
			ProtocolMode: registrydomain.MCPProtocolModeModern,
		},
	)
	require.NoError(t, err)
	if perPrincipalSource {
		registry.MCPTarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModePassthrough}
	}
	consumer := &consumerdomain.Consumer{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gatewayID,
		Type:        consumerdomain.TypeMCP,
		Slug:        "virtual",
		Active:      true,
		AuthIDs:     []ids.AuthID{authID},
		RegistryIDs: []ids.RegistryID{registry.ID},
	}
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{{
		Consumer:   consumer,
		Registries: []*registrydomain.Registry{registry},
	}})
	finder := upstreamIntegrationFinder{data: data}
	connector := mcpclient.NewModernSubscriptionConnector(8192, time.Minute)
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return([]appmcp.Tool{}, nil).Maybe()
	policy := appmcp.NewSubscriptionPolicyWithUpstream(
		finder,
		scoper,
		composer,
		nil,
		nil,
		connector,
	)
	targets := appmcp.NewSubscriptionTargetResolver(finder, scoper, nil)
	refresher, ok := targets.(appmcp.SubscriptionTargetRefresher)
	require.True(t, ok)
	multiplexer, err := appmcp.NewSubscriptionMultiplexer(
		context.Background(),
		connector,
		policy.AuthorizeEvent,
		appmcp.SubscriptionMultiplexerOptions{
			MaxListeners:         maxListeners,
			MaxPerOrigin:         maxPerOrigin,
			QueueCapacity:        4,
			ReconnectAttempts:    0,
			ReconnectBackoffMin:  time.Millisecond,
			ReconnectBackoffMax:  time.Millisecond,
			AuthorizationTimeout: time.Second,
			Refresher:            refresher,
		},
	)
	require.NoError(t, err)
	leaseRegistry := appmcp.NewSubscriptionRegistry(appmcp.SubscriptionCaps{
		MaxStreams:      maxStreams,
		MaxPerConsumer:  4,
		MaxPerPrincipal: 4,
	})
	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(nil)
	executor := pluginmocks.NewExecutor(t)
	executor.EXPECT().RunStage(mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	handler := mcphttp.NewHandlerWithSubscriptions(
		mcphttp.NewRPCGateway(
			composer,
			appmcp.NewPluginRunner(executor, discardLogger()),
			limiter,
		),
		scoper,
		mcphttp.MRTRSupport{},
		mcphttp.TasksSupport{},
		mcphttp.SubscriptionsSupport{
			On:             true,
			MaxLifetime:    time.Minute,
			ReauthInterval: time.Hour,
			Keepalive:      25 * time.Millisecond,
			MaxEventBytes:  8192,
			MaxURIs:        8,
			Registry:       leaseRegistry,
			Policy:         policy,
			Upstream:       true,
			Targets:        targets,
			Source:         multiplexer,
		},
	)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(func(c *fiber.Ctx) error {
		subject := c.Get("X-Test-Subject")
		ctx := identity.WithPrincipal(c.UserContext(), &identity.Principal{
			Subject: subject,
			Issuer:  "integration",
		})
		ctx = appconsumer.WithAuthID(ctx, authID)
		ctx = appconsumer.WithGatewayID(ctx, gatewayID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	})
	app.Post(mcpPath, handler.Handle)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- app.Listener(listener) }()
	harness := &upstreamIntegrationHarness{
		url:         "http://" + listener.Addr().String() + mcpPath,
		app:         app,
		multiplexer: multiplexer,
		registry:    leaseRegistry,
		served:      served,
	}
	t.Cleanup(func() { harness.close(t) })
	return harness
}

func (h *upstreamIntegrationHarness) close(t *testing.T) {
	t.Helper()
	h.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := h.multiplexer.Close(ctx); err != nil {
			h.closeErr = err
			return
		}
		if err := h.registry.Drain(ctx); err != nil {
			h.closeErr = err
			return
		}
		if err := h.app.ShutdownWithTimeout(time.Second); err != nil {
			h.closeErr = err
			return
		}
		h.closeErr = <-h.served
	})
	require.NoError(t, h.closeErr)
}

func (h *upstreamIntegrationHarness) open(
	t *testing.T,
	subject string,
) (*http.Response, *bufio.Reader) {
	t.Helper()
	req, err := http.NewRequest(
		http.MethodPost,
		h.url,
		strings.NewReader(listenRequest(`"notifications":["toolsListChanged","promptsListChanged"]`)),
	)
	require.NoError(t, err)
	req.Header = listenHeaders()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Subject", subject)
	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Mcp-Session-Id"))
	return resp, bufio.NewReader(resp.Body)
}

func (h *upstreamIntegrationHarness) requestBody(t *testing.T, subject string) []byte {
	t.Helper()
	req, err := http.NewRequest(
		http.MethodPost,
		h.url,
		strings.NewReader(listenRequest(`"notifications":["toolsListChanged"]`)),
	)
	require.NoError(t, err)
	req.Header = listenHeaders()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Subject", subject)
	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.NotEqual(t, "text/event-stream", resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}

func readUpstreamIntegrationFrame(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	var data string
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			return data
		}
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		}
	}
}

func TestSubscriptionsListenRealFiberAndModernUpstream(t *testing.T) {
	upstream := newUpstreamIntegrationServer(t, true)
	scoper := &upstreamIntegrationScoper{revoked: make(map[string]bool)}
	harness := newUpstreamIntegrationHarness(t, upstream, scoper)

	firstResponse, first := harness.open(t, "first")
	defer firstResponse.Body.Close()
	secondResponse, second := harness.open(t, "second")
	defer secondResponse.Body.Close()

	firstAck := readUpstreamIntegrationFrame(t, first)
	secondAck := readUpstreamIntegrationFrame(t, second)
	require.Contains(t, firstAck, "notifications/subscriptions/acknowledged")
	require.Contains(t, firstAck, "toolsListChanged")
	require.NotContains(t, firstAck, "promptsListChanged")
	require.Contains(t, secondAck, "notifications/subscriptions/acknowledged")
	require.Equal(t, int32(1), upstream.listens.Load())

	scoper.revoke("first")
	upstream.events <- `{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}`

	firstTerminal := readUpstreamIntegrationFrame(t, first)
	secondEvent := readUpstreamIntegrationFrame(t, second)
	require.Contains(t, firstTerminal, `"result"`)
	require.NotContains(t, firstTerminal, "revoked")
	require.Contains(t, secondEvent, "notifications/tools/list_changed")

	require.NoError(t, secondResponse.Body.Close())
	require.Eventually(t, func() bool {
		select {
		case <-upstream.canceled:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	harness.close(t)
}

func TestSubscriptionsListenAllUnsupportedAcknowledgesThenTerminates(t *testing.T) {
	upstream := newUpstreamIntegrationServer(t, false)
	scoper := &upstreamIntegrationScoper{revoked: make(map[string]bool)}
	harness := newUpstreamIntegrationHarness(t, upstream, scoper)

	response, reader := harness.open(t, "unsupported")
	defer response.Body.Close()

	ack := readUpstreamIntegrationFrame(t, reader)
	terminal := readUpstreamIntegrationFrame(t, reader)
	require.Contains(t, ack, "notifications/subscriptions/acknowledged")
	require.NotContains(t, ack, "toolsListChanged")
	require.NotContains(t, ack, "promptsListChanged")
	require.Contains(t, terminal, `"result"`)
	require.Equal(t, int32(0), upstream.listens.Load())

	harness.close(t)
}

func TestSubscriptionsListenUpstreamCapacityMatchesNorthboundRefusalBytes(t *testing.T) {
	t.Parallel()
	baselineUpstream := newUpstreamIntegrationServer(t, true)
	baselineScoper := &upstreamIntegrationScoper{revoked: make(map[string]bool)}
	baseline := newUpstreamIntegrationHarnessWithCaps(
		t,
		baselineUpstream,
		baselineScoper,
		4,
		4,
		1,
		false,
	)
	baselineResponse, baselineReader := baseline.open(t, "baseline-first")
	_ = readUpstreamIntegrationFrame(t, baselineReader)
	want := baseline.requestBody(t, "baseline-second")
	require.Contains(t, string(want), `"code":-32026`)
	require.NoError(t, baselineResponse.Body.Close())

	tests := []struct {
		name         string
		maxListeners int
		maxPerOrigin int
	}{
		{name: "global", maxListeners: 1, maxPerOrigin: 4},
		{name: "per origin", maxListeners: 4, maxPerOrigin: 1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			upstream := newUpstreamIntegrationServer(t, true)
			scoper := &upstreamIntegrationScoper{revoked: make(map[string]bool)}
			harness := newUpstreamIntegrationHarnessWithCaps(
				t,
				upstream,
				scoper,
				test.maxListeners,
				test.maxPerOrigin,
				4,
				true,
			)
			firstResponse, firstReader := harness.open(t, "first")
			_ = readUpstreamIntegrationFrame(t, firstReader)
			got := harness.requestBody(t, "second")
			require.Equal(t, want, got)
			require.Equal(t, int32(1), upstream.listens.Load())
			require.NoError(t, firstResponse.Body.Close())
		})
	}
}

func TestSubscriptionsListenHidesNonCapacityAttachFailure(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamIntegrationServer(t, true)
	upstream.listenFailure = "credential provider leaked detail"
	scoper := &upstreamIntegrationScoper{revoked: make(map[string]bool)}
	harness := newUpstreamIntegrationHarness(t, upstream, scoper)
	body := harness.requestBody(t, "attach-failure")
	require.Contains(t, string(body), `"code":-32005`)
	require.Contains(t, string(body), appmcp.ErrUpstreamUnavailable.Error())
	require.NotContains(t, string(body), upstream.listenFailure)
	require.NotContains(t, string(body), `"code":-32026`)
}
