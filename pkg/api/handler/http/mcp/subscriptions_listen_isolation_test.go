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
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/stretchr/testify/require"
)

type isolationAuthorizationKey struct{}

type isolationConnector struct {
	mu      sync.Mutex
	streams []*isolationStream
}

func (c *isolationConnector) Prepare(
	_ context.Context,
	target appmcp.Target,
) (appmcp.PreparedSubscription, error) {
	return appmcp.PreparedSubscription{
		Key: appmcp.SubscriptionSourceKey{
			TargetDigest:          sha256.Sum256([]byte(target.URL)),
			OriginDigest:          sha256.Sum256([]byte("https://upstream.example")),
			CredentialFingerprint: sha256.Sum256([]byte(target.Headers["Authorization"])),
			ProtocolVersion:       "2026-07-28",
			Capabilities:          appmcp.ListChangedCapabilities{Tools: true},
		},
		Capabilities: appmcp.ListChangedCapabilities{Tools: true},
	}, nil
}

func (c *isolationConnector) Open(
	_ context.Context,
	_ appmcp.Target,
	prepared appmcp.PreparedSubscription,
) (appmcp.SubscriptionStream, error) {
	stream := &isolationStream{
		acknowledged: prepared.Capabilities,
		events:       make(chan appmcp.SubscriptionEvent, 1),
	}
	c.mu.Lock()
	c.streams = append(c.streams, stream)
	c.mu.Unlock()
	return stream, nil
}

func (c *isolationConnector) opened() []*isolationStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*isolationStream(nil), c.streams...)
}

type isolationStream struct {
	acknowledged appmcp.ListChangedCapabilities
	events       chan appmcp.SubscriptionEvent
}

func (s *isolationStream) Acknowledged() appmcp.ListChangedCapabilities {
	return s.acknowledged
}

func (s *isolationStream) Next(ctx context.Context) (appmcp.SubscriptionEvent, error) {
	select {
	case event := <-s.events:
		return event, nil
	case <-ctx.Done():
		return appmcp.SubscriptionEvent{}, ctx.Err()
	}
}

func (*isolationStream) Close() error { return nil }

func isolationMultiplexer(
	t *testing.T,
	connector *isolationConnector,
	authorize appmcp.SubscriptionAuthorization,
) *appmcp.SubscriptionMultiplexer {
	t.Helper()
	multiplexer, err := appmcp.NewSubscriptionMultiplexer(
		context.Background(),
		connector,
		authorize,
		appmcp.SubscriptionMultiplexerOptions{
			MaxListeners:        8,
			MaxPerOrigin:        8,
			QueueCapacity:       2,
			ReconnectAttempts:   0,
			ReconnectBackoffMin: time.Millisecond,
			ReconnectBackoffMax: time.Millisecond,
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, multiplexer.Close(ctx))
	})
	return multiplexer
}

func TestSubscriptionsListenIsolationAcrossAuthorizationBindings(t *testing.T) {
	base := appmcp.SubscriptionIdentity{
		GatewayID:            "gateway",
		ConsumerID:           "consumer",
		PrincipalFingerprint: "principal",
		AuthID:               "auth",
		RegistryID:           "registry",
		RoleScopeFingerprint: "role",
		Path:                 "/virtual/mcp",
	}
	tests := []struct {
		name   string
		mutate func(*appmcp.SubscriptionIdentity)
	}{
		{name: "gateway", mutate: func(id *appmcp.SubscriptionIdentity) { id.GatewayID = "other" }},
		{name: "consumer", mutate: func(id *appmcp.SubscriptionIdentity) { id.ConsumerID = "other" }},
		{name: "principal", mutate: func(id *appmcp.SubscriptionIdentity) { id.PrincipalFingerprint = "other" }},
		{name: "auth id", mutate: func(id *appmcp.SubscriptionIdentity) { id.AuthID = "other" }},
		{name: "registry", mutate: func(id *appmcp.SubscriptionIdentity) { id.RegistryID = "other" }},
		{name: "role scope", mutate: func(id *appmcp.SubscriptionIdentity) { id.RoleScopeFingerprint = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connector := &isolationConnector{}
			multiplexer := isolationMultiplexer(
				t,
				connector,
				func(
					ctx context.Context,
					identity appmcp.SubscriptionIdentity,
					_ appmcp.SubscriptionSourceKey,
					_ appmcp.NotificationKind,
				) (bool, error) {
					if authorized, _ := ctx.Value(isolationAuthorizationKey{}).(bool); !authorized {
						return false, appmcp.ErrSubscriptionRevoked
					}
					if identity != base {
						return false, appmcp.ErrSubscriptionRevoked
					}
					return true, nil
				},
			)
			target := appmcp.Target{
				URL:     "https://upstream.example/mcp",
				Headers: map[string]string{"Authorization": "Bearer shared"},
			}
			allowed, _, err := multiplexer.Attach(
				context.WithValue(context.Background(), isolationAuthorizationKey{}, true),
				[]appmcp.SubscriptionRequest{{
					Identity:  base,
					Target:    target,
					Requested: appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged),
				}},
			)
			require.NoError(t, err)
			deniedIdentity := base
			test.mutate(&deniedIdentity)
			denied, _, err := multiplexer.Attach(
				context.WithValue(context.Background(), isolationAuthorizationKey{}, false),
				[]appmcp.SubscriptionRequest{{
					Identity:  deniedIdentity,
					Target:    target,
					Requested: appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged),
				}},
			)
			require.NoError(t, err)
			require.Len(t, connector.opened(), 1)

			connector.opened()[0].events <- appmcp.SubscriptionEvent{
				Kind: appmcp.NotificationToolsListChanged,
			}
			select {
			case event := <-allowed.Events():
				require.Equal(t, appmcp.NotificationToolsListChanged, event.Kind)
			case <-time.After(time.Second):
				t.Fatal("authorized binding did not receive the event")
			}
			select {
			case <-denied.Done():
				require.ErrorIs(t, denied.Err(), appmcp.ErrSubscriptionRevoked)
			case <-time.After(time.Second):
				t.Fatal("revoked binding did not terminate")
			}
			allowed.Close()
		})
	}
}

func TestSubscriptionsListenIsolationDoesNotShareAcrossCredentials(t *testing.T) {
	connector := &isolationConnector{}
	multiplexer := isolationMultiplexer(
		t,
		connector,
		func(
			context.Context,
			appmcp.SubscriptionIdentity,
			appmcp.SubscriptionSourceKey,
			appmcp.NotificationKind,
		) (bool, error) {
			return true, nil
		},
	)
	for _, credential := range []string{"Bearer first", "Bearer second"} {
		handle, _, err := multiplexer.Attach(context.Background(), []appmcp.SubscriptionRequest{{
			Identity: appmcp.SubscriptionIdentity{
				GatewayID:            "gateway",
				ConsumerID:           "consumer",
				PrincipalFingerprint: "principal",
				AuthID:               "auth",
				RegistryID:           "registry",
				RoleScopeFingerprint: "role",
				Path:                 "/virtual/mcp",
			},
			Target: appmcp.Target{
				URL:     "https://upstream.example/mcp",
				Headers: map[string]string{"Authorization": credential},
			},
			Requested: appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged),
		}})
		require.NoError(t, err)
		t.Cleanup(handle.Close)
	}
	require.Eventually(t, func() bool { return len(connector.opened()) == 2 }, time.Second, time.Millisecond)
}
