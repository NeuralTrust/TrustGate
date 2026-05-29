// Package cachetest provides cache test doubles shared across app-layer tests.
package cachetest

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

type noopPublisher struct{}

func (noopPublisher) Publish(context.Context, event.Event) error { return nil }

// NoopPublisher returns an EventPublisher that discards every event. Use it in
// unit tests that exercise services which publish cache-invalidation events but
// do not assert on the events themselves.
func NoopPublisher() cache.EventPublisher { return noopPublisher{} }
