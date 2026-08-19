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
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const (
	// integrationWriteTimeout is the server write timeout the lifetime must clear
	// by the fixed ten-second margin: 1 + 10 ≤ 12.
	integrationWriteTimeout = 12 * time.Second

	// integrationLifetime is the whole lease, short enough to watch end to end.
	integrationLifetime = time.Second

	// integrationKeepalive puts several frames on the wire inside one lifetime,
	// which is what makes incremental delivery observable rather than inferred.
	integrationKeepalive = 150 * time.Millisecond

	integrationStreams = 4

	// integrationDrainBudget is what a shutdown gives every live lease to write
	// its terminal frame and let go of its capacity.
	integrationDrainBudget = 5 * time.Second

	// integrationClientTimeout bounds the whole exchange, so a lease that never
	// terminates fails the test rather than hanging it.
	integrationClientTimeout = 30 * time.Second
)

// integrationServer is a real Fiber app on a real socket. It is the one place in
// the suite that uses a real clock, because what is under test is the interaction
// between the lease deadline, the write timeout, and the connection.
type integrationServer struct {
	url      string
	app      *fiber.App
	registry *appmcp.SubscriptionRegistry
}

func newIntegrationServer(t *testing.T, lifetime, keepalive time.Duration) *integrationServer {
	t.Helper()

	registry := appmcp.NewSubscriptionRegistry(appmcp.SubscriptionCaps{
		MaxStreams:      subscriptionsCap,
		MaxPerConsumer:  subscriptionsCap,
		MaxPerPrincipal: subscriptionsCap,
	})
	subs := mcphttp.SubscriptionsSupport{
		On:             true,
		MaxLifetime:    lifetime,
		ReauthInterval: subscriptionsMaxLifetime,
		Keepalive:      keepalive,
		MaxEventBytes:  subscriptionsMaxEventBytes,
		MaxURIs:        subscriptionsMaxURIs,
		Registry:       registry,
		Policy:         mocks.NewSubscriptionPolicy(t),
	}

	authID := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Name:      "virtual",
		Type:      consumerdomain.TypeMCP,
		Slug:      "virtual",
		Active:    true,
		AuthIDs:   []ids.AuthID{authID},
	}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: cons, Registries: []*registrydomain.Registry{modernMCPRegistry(t, gwID)}},
	})
	requestTrace := trace.New("t-subscriptions", trace.Metadata{Kind: events.KindMCP})

	app := fiber.New(fiber.Config{
		WriteTimeout:          integrationWriteTimeout,
		DisableStartupMessage: true,
	})
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = trace.NewContext(ctx, requestTrace)
		c.SetUserContext(ctx)
		return c.Next()
	})
	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(nil)
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return([]appmcp.Tool{}, nil).Maybe()
	executor := pluginmocks.NewExecutor(t)
	executor.EXPECT().RunStage(mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	handler := mcphttp.NewHandlerWithSubscriptions(
		mcphttp.NewRPCGateway(
			composer,
			appmcp.NewPluginRunner(executor, discardLogger()),
			limiter,
		),
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
		mcphttp.MRTRSupport{},
		mcphttp.TasksSupport{},
		subs,
	)
	app.Post(mcpPath, handler.Handle)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- app.Listener(listener) }()
	t.Cleanup(func() {
		require.NoError(t, app.ShutdownWithTimeout(5*time.Second))
		require.NoError(t, <-served)
	})

	return &integrationServer{
		url:      "http://" + listener.Addr().String() + mcpPath,
		app:      app,
		registry: registry,
	}
}

// openStream issues a real listen request and hands back the response with its
// body still open, so the caller reads frames as the server writes them.
func (s *integrationServer) openStream(t *testing.T) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		s.url,
		strings.NewReader(listenRequest(`"notifications":["toolsListChanged"]`)),
	)
	require.NoError(t, err)
	req.Header = listenHeaders()
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

	client := &http.Client{Timeout: integrationClientTimeout}
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	require.Equal(t, "text/event-stream", resp.Header.Get(fiber.HeaderContentType))
	require.Empty(t, resp.Header.Get("Mcp-Session-Id"), "a lease must not mint a session")
	return resp
}

// timedFrame is one frame and when the client saw it, which is how incremental
// delivery is told apart from one burst at close.
type timedFrame struct {
	text string
	at   time.Time
}

// readFrames consumes the response to EOF, recording each SSE frame's arrival.
func readFrames(t *testing.T, body io.ReadCloser) []timedFrame {
	t.Helper()
	defer func() { require.NoError(t, body.Close()) }()

	reader := bufio.NewReader(body)
	frames := make([]timedFrame, 0, 8)
	var current strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if line == "\n" {
				if text := strings.TrimSuffix(current.String(), "\n"); text != "" {
					frames = append(frames, timedFrame{text: text, at: time.Now()})
				}
				current.Reset()
			} else {
				current.WriteString(line)
			}
		}
		if err != nil {
			require.ErrorIs(t, err, io.EOF, "the stream did not close cleanly")
			return frames
		}
	}
}

// A lease that runs to its deadline closes the connection cleanly, and its frames
// reach the client as they are written rather than all at once at close.
func TestSubscriptionsListen_Integration_DeadlineClosesCleanly(t *testing.T) {
	server := newIntegrationServer(t, integrationLifetime, integrationKeepalive)

	opened := time.Now()
	resp := server.openStream(t)
	frames := readFrames(t, resp.Body)

	require.GreaterOrEqual(t, len(frames), 3, "one lifetime must carry the ack, a keepalive and the terminal frame")
	require.Contains(t, frames[0].text, "notifications/subscriptions/acknowledged")
	require.Contains(t, frames[len(frames)-1].text, `"result"`)

	require.Less(t, frames[0].at.Sub(opened), integrationLifetime/2,
		"the ack was buffered until the response closed")
	require.Greater(t, frames[len(frames)-1].at.Sub(frames[0].at), integrationKeepalive,
		"every frame arrived in one burst at close")

	for _, frame := range frames {
		require.True(t,
			strings.HasPrefix(frame.text, "event: message\ndata: ") || strings.HasPrefix(frame.text, ": "),
			"unexpected frame %q", frame.text)
	}
}

// Shutdown drains every live lease inside its budget: each stream ends on its own
// terminal frame, and the drain reports completion rather than timing out.
func TestSubscriptionsListen_Integration_ShutdownDrainsLiveStreams(t *testing.T) {
	server := newIntegrationServer(t, subscriptionsMaxLifetime, integrationKeepalive)

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		closed []time.Time
	)
	for i := 0; i < integrationStreams; i++ {
		resp := server.openStream(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			frames := readFrames(t, resp.Body)
			mu.Lock()
			defer mu.Unlock()
			closed = append(closed, time.Now())
			require.NotEmpty(t, frames)
			require.Contains(t, frames[len(frames)-1].text, `"result"`)
		}()
	}
	require.Eventually(t, func() bool { return server.registry.Live() == integrationStreams },
		2*time.Second, 10*time.Millisecond, "the leases were not all claimed")

	ctx, cancel := context.WithTimeout(context.Background(), integrationDrainBudget)
	defer cancel()
	drained := time.Now()
	require.NoError(t, server.registry.Drain(ctx), "the drain did not finish inside its budget")
	wg.Wait()

	require.Zero(t, server.registry.Live())
	for _, at := range closed {
		require.Less(t, at.Sub(drained), integrationDrainBudget,
			"a stream outlived the drain rather than being ended by it")
	}
}
