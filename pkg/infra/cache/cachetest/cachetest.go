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
