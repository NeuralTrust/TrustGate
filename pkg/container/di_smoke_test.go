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

package container_test

import (
	"encoding/base64"
	"strings"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/container/modules"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/NeuralTrust/TrustGate/pkg/server"
	"github.com/alicebob/miniredis/v2"
	"go.uber.org/dig"
)

func TestDISmoke_PlaneAwareModuleSets_Register(t *testing.T) {
	cases := []struct {
		plane  string
		dbless bool
	}{
		{"admin", false},
		{"proxy", false},
		{"mcp", false},
		{"run", false},
		{"proxy", true},
		{"mcp", true},
	}
	for _, tc := range cases {
		if _, err := container.New(modules.All(tc.plane, tc.dbless)...); err != nil {
			t.Fatalf("New(modules.All(%q, %v)...): %v", tc.plane, tc.dbless, err)
		}
	}
}

func TestDISmoke_DBLessDataPlane_ResolvesRepositoriesWithoutPool(t *testing.T) {
	t.Setenv("POSTGRES_LOGIN", "aws")
	t.Setenv("CONFIG_SYNC_DATA_PLANE_ENABLED", "true")
	t.Setenv("CONFIG_SYNC_TOKEN", "smoke-token")
	t.Setenv("CONFIG_SYNC_GRPC_ENDPOINT", "admin.example.com:8083")
	t.Setenv("CONFIG_SYNC_LKG_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	for _, key := range []string{
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
		"DB_HOST",
		"DB_USER",
		"DB_PASSWORD",
		"DB_NAME",
	} {
		t.Setenv(key, "")
	}
	for _, plane := range []string{"proxy", "mcp"} {
		t.Run(plane, func(t *testing.T) {
			c, err := container.New(modules.All(plane, true)...)
			if err != nil {
				t.Fatalf("New(modules.All(%q, true)...): %v", plane, err)
			}
			if err := c.Invoke(func(
				conn *database.Connection,
				store configsync.ConfigStore[*readmodel.Snapshot],
				gateways gatewaydomain.Repository,
				consumers consumerdomain.Repository,
			) {
				if conn != nil {
					t.Fatal("DB-less data plane resolved a non-nil *database.Connection: the pgx pool was built")
				}
				if store == nil {
					t.Fatal("config snapshot store resolved to nil")
				}
				if gateways == nil || consumers == nil {
					t.Fatal("snapshot-backed repositories resolved to nil")
				}
			}); err != nil {
				t.Fatalf("Invoke(snapshot repositories): %v", err)
			}
		})
	}
}

func setDBLessSmokeEnv(t *testing.T) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	t.Setenv("REDIS_HOST", mr.Host())
	t.Setenv("REDIS_PORT", mr.Port())
	t.Setenv("KAFKA_BROKERS", "localhost:9092")
	t.Setenv("GATEWAY_BASE_DOMAIN", "example.com")
	t.Setenv("CONFIG_SYNC_DATA_PLANE_ENABLED", "true")
	t.Setenv("CONFIG_SYNC_TOKEN", "smoke-token")
	t.Setenv("CONFIG_SYNC_GRPC_ENDPOINT", "admin.example.com:8083")
	t.Setenv("CONFIG_SYNC_TLS_INSECURE", "true")
	t.Setenv("CONFIG_SYNC_LKG_PATH", t.TempDir()+"/snapshot.lkg")
	t.Setenv("CONFIG_SYNC_LKG_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SERVER_SECRET_KEY", strings.Repeat("smoke-server-secret-", 3))
}

func TestDISmoke_DBLessDataPlane_ResolvesConfigSyncWorker(t *testing.T) {
	setDBLessSmokeEnv(t)

	c, err := container.New(modules.All("mcp", true)...)
	if err != nil {
		t.Fatalf("New(modules.All(mcp, true)...): %v", err)
	}

	if err := c.Invoke(func(
		_ *configsync.Worker[*readmodel.Snapshot],
		_ configsync.ConfigStore[*readmodel.Snapshot],
		conn *database.Connection,
		vault vaultdomain.Repository,
	) {
		if conn != nil {
			t.Fatal("DB-less mcp graph resolved a non-nil *database.Connection")
		}
		if vault == nil {
			t.Fatal("DB-less mcp graph resolved a nil vault repository")
		}
	}); err != nil {
		t.Fatalf("Invoke(configsync worker + store + redis vault): %v", err)
	}
}

func TestDISmoke_DBLessDataPlane_ResolvesNamedServer(t *testing.T) {
	for _, plane := range []string{"proxy", "mcp"} {
		t.Run(plane, func(t *testing.T) {
			setDBLessSmokeEnv(t)
			c, err := container.New(modules.All(plane, true)...)
			if err != nil {
				t.Fatalf("New(modules.All(%q, true)...): %v", plane, err)
			}
			resolve := func(p dblessServerParam) {
				if p.Srv == nil {
					t.Fatalf("DB-less %q graph resolved a nil server", plane)
				}
			}
			var invErr error
			switch plane {
			case "proxy":
				invErr = c.Invoke(func(p dblessProxyServerParam) { resolve(dblessServerParam{Srv: p.Srv}) })
			case "mcp":
				invErr = c.Invoke(func(p dblessMCPServerParam) { resolve(dblessServerParam{Srv: p.Srv}) })
			}
			if invErr != nil {
				t.Fatalf("Invoke(server.Server name=%q): %v", plane, invErr)
			}
		})
	}
}

type dblessServerParam struct {
	Srv server.Server
}

type dblessProxyServerParam struct {
	dig.In
	Srv server.Server `name:"proxy"`
}

type dblessMCPServerParam struct {
	dig.In
	Srv server.Server `name:"mcp"`
}

func TestDISmoke_ControlPlane_BuildsControlConfigSync(t *testing.T) {
	for _, plane := range []string{"admin", "run"} {
		t.Run(plane, func(t *testing.T) {
			c, err := container.New(modules.All(plane, false)...)
			if err != nil {
				t.Fatalf("New(modules.All(%q, false)...): %v", plane, err)
			}
			if err := c.Invoke(func(holder *appsnapshot.Holder) {
				if holder == nil {
					t.Fatal("ControlConfigSync did not provide *appsnapshot.Holder")
				}
			}); err != nil {
				t.Fatalf("Invoke(*appsnapshot.Holder): %v", err)
			}
		})
	}
}
