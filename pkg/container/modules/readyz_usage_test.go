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
	"log/slog"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/dig"
)

type emptyStateCache struct{}

func (emptyStateCache) Save(context.Context, usagedomain.TenantState) (bool, error) { return true, nil }
func (emptyStateCache) LoadAll(context.Context) ([]usagedomain.TenantState, error)  { return nil, nil }

func TestAdminUsageReadinessFollowsTheFlag(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		for _, plane := range []string{"admin", "proxy"} {
			c, err := container.New(container.WithModule(adminReadiness(plane)))
			require.NoError(t, err)
			require.NoError(t, c.Provide(func() *appsnapshot.Dispatcher { return &appsnapshot.Dispatcher{} }))
			require.NoError(t, c.Provide(func() *config.Config {
				return &config.Config{Usage: config.UsageConfig{Enabled: enabled, ReadyTimeout: time.Hour}}
			}))
			require.NoError(t, c.Provide(func() *slog.Logger { return slog.Default() }))
			store := appusage.NewStore(emptyStateCache{}, nil)
			require.NoError(t, c.Provide(func() appusage.Reader { return store }))

			var check adminUsageReadiness
			require.NoError(t, c.Invoke(func(p struct {
				dig.In
				Check adminUsageReadiness `optional:"true"`
			}) {
				check = p.Check
			}))
			if !enabled || plane != "admin" {
				assert.Nil(t, check, "plane %s enabled %v", plane, enabled)
				continue
			}
			require.NotNil(t, check)
			assert.ErrorIs(t, check(context.Background()), appusage.ErrListNotReady)
			require.NoError(t, store.Restore(context.Background()))
			assert.NoError(t, check(context.Background()))
		}
	}
}
