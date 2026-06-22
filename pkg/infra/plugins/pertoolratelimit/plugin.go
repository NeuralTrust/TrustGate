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

package pertoolratelimit

import (
	"context"
	"net/http"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/go-redis/redis/v8"
)

const PluginName = "per_tool_rate_limiter"

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	redis    *redis.Client
	registry *adapter.Registry
	now      func() time.Time
}

type Option func(*Plugin)

func WithClock(now func() time.Time) Option {
	return func(p *Plugin) { p.now = now }
}

func New(redisClient *redis.Client, adapters *adapter.Registry, opts ...Option) *Plugin {
	p := &Plugin{
		redis:    redisClient,
		registry: adapters,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreResponse}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	return &appplugins.Result{StatusCode: http.StatusOK}, nil
}
