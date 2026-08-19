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

package modules

import (
	"context"
	"sync"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/stretchr/testify/require"
)

type shutdownSubscriptionConnector struct {
	stream *shutdownSubscriptionStream
	key    appmcp.SubscriptionSourceKey
}

func (c *shutdownSubscriptionConnector) Prepare(
	context.Context,
	appmcp.Target,
) (appmcp.PreparedSubscription, error) {
	return appmcp.PreparedSubscription{
		Key:          c.key,
		Capabilities: c.key.Capabilities,
	}, nil
}

func (c *shutdownSubscriptionConnector) Open(
	context.Context,
	appmcp.Target,
	appmcp.PreparedSubscription,
) (appmcp.SubscriptionStream, error) {
	return c.stream, nil
}

type shutdownSubscriptionStream struct {
	started chan struct{}
	joined  chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (s *shutdownSubscriptionStream) Acknowledged() appmcp.ListChangedCapabilities {
	return appmcp.ListChangedCapabilities{Tools: true}
}

func (s *shutdownSubscriptionStream) Next(ctx context.Context) (appmcp.SubscriptionEvent, error) {
	s.once.Do(func() { close(s.started) })
	if s.release != nil {
		<-s.release
		close(s.joined)
		return appmcp.SubscriptionEvent{}, ctx.Err()
	}
	<-ctx.Done()
	close(s.joined)
	return appmcp.SubscriptionEvent{}, ctx.Err()
}

func (*shutdownSubscriptionStream) Close() error { return nil }

func TestMCPShutdownClosesSouthboundBeforeNorthboundDrain(t *testing.T) {
	stream := &shutdownSubscriptionStream{
		started: make(chan struct{}),
		joined:  make(chan struct{}),
	}
	key := appmcp.SubscriptionSourceKey{
		Capabilities: appmcp.ListChangedCapabilities{Tools: true},
	}
	multiplexer, err := appmcp.NewSubscriptionMultiplexer(
		context.Background(),
		&shutdownSubscriptionConnector{stream: stream, key: key},
		func(
			context.Context,
			appmcp.SubscriptionIdentity,
			appmcp.SubscriptionSourceKey,
			appmcp.NotificationKind,
		) (bool, error) {
			return true, nil
		},
		appmcp.SubscriptionMultiplexerOptions{
			MaxListeners:        1,
			MaxPerOrigin:        1,
			QueueCapacity:       1,
			ReconnectAttempts:   0,
			ReconnectBackoffMin: time.Millisecond,
			ReconnectBackoffMax: time.Millisecond,
		},
	)
	require.NoError(t, err)
	handle, _, err := multiplexer.Attach(context.Background(), []appmcp.SubscriptionRequest{{
		Target:    appmcp.Target{URL: "https://upstream.example/mcp"},
		Requested: appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged),
	}})
	require.NoError(t, err)
	require.NotNil(t, handle)
	<-stream.started

	registry := appmcp.NewSubscriptionRegistry(appmcp.SubscriptionCaps{
		MaxStreams:      1,
		MaxPerConsumer:  1,
		MaxPerPrincipal: 1,
	})
	lease, err := registry.Claim(context.Background(), appmcp.IsolationKey{ConsumerID: "consumer"})
	require.NoError(t, err)
	drainedAfterJoin := make(chan bool, 1)
	go func() {
		<-lease.Context().Done()
		select {
		case <-stream.joined:
			drainedAfterJoin <- true
		default:
			drainedAfterJoin <- false
		}
		lease.Release()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, mcpSubscriptionShutdownHook(multiplexer, registry)(ctx))
	require.True(t, <-drainedAfterJoin)
}

func TestMCPUpstreamShutdownHookPropagatesDeadline(t *testing.T) {
	release := make(chan struct{})
	stream := &shutdownSubscriptionStream{
		started: make(chan struct{}),
		joined:  make(chan struct{}),
		release: release,
	}
	key := appmcp.SubscriptionSourceKey{
		Capabilities: appmcp.ListChangedCapabilities{Tools: true},
	}
	multiplexer, err := appmcp.NewSubscriptionMultiplexer(
		context.Background(),
		&shutdownSubscriptionConnector{stream: stream, key: key},
		func(
			context.Context,
			appmcp.SubscriptionIdentity,
			appmcp.SubscriptionSourceKey,
			appmcp.NotificationKind,
		) (bool, error) {
			return true, nil
		},
		appmcp.SubscriptionMultiplexerOptions{
			MaxListeners:        1,
			MaxPerOrigin:        1,
			QueueCapacity:       1,
			ReconnectAttempts:   0,
			ReconnectBackoffMin: time.Millisecond,
			ReconnectBackoffMax: time.Millisecond,
		},
	)
	require.NoError(t, err)
	_, _, err = multiplexer.Attach(context.Background(), []appmcp.SubscriptionRequest{{
		Target:    appmcp.Target{URL: "https://upstream.example/mcp"},
		Requested: appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged),
	}})
	require.NoError(t, err)
	<-stream.started

	registry := appmcp.NewSubscriptionRegistry(appmcp.SubscriptionCaps{
		MaxStreams:      1,
		MaxPerConsumer:  1,
		MaxPerPrincipal: 1,
	})
	lease, err := registry.Claim(context.Background(), appmcp.IsolationKey{ConsumerID: "consumer"})
	require.NoError(t, err)
	go func() {
		<-lease.Context().Done()
		lease.Release()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = mcpSubscriptionShutdownHook(multiplexer, registry)(ctx)
	require.ErrorIs(t, err, context.Canceled)
	select {
	case <-lease.Context().Done():
		t.Fatal("northbound drain began before the southbound listener joined")
	default:
	}
	close(release)
	require.NoError(t, mcpSubscriptionShutdownHook(multiplexer, registry)(context.Background()))
	require.Equal(t, 0, registry.Live())
	require.Nil(t, upstreamSubscriptionCloseHook(nil))
	require.Nil(t, mcpSubscriptionShutdownHook(nil, nil))
}
