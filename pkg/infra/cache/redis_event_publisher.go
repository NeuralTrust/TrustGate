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

package cache

import (
	"context"
	"encoding/json"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/channel"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

type RedisPublisherInitializer func(cache Client, channel channel.Channel) EventPublisher

var _ EventPublisher = (*redisEventPublisher)(nil)

type redisEventPublisher struct {
	cache   Client
	channel channel.Channel
}

func NewRedisEventPublisher(cache Client, channel channel.Channel) EventPublisher {
	return &redisEventPublisher{
		cache:   cache,
		channel: channel,
	}
}

func (p *redisEventPublisher) Publish(ctx context.Context, ev event.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	envelope := RedisMessage{
		Type:  ev.Type(),
		Event: b,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return p.cache.RedisClient().Publish(ctx, string(p.channel), data).Err()
}
