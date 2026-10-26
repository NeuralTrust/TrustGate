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

package config

import (
	"encoding/base64"
	stderrors "errors"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func TestGetUsageConfigDefaults(t *testing.T) {
	cfg := getUsageConfig()
	want := UsageConfig{
		ReadyTimeout:           defaultUsageReadyTimeout,
		GRPCKeepaliveTime:      30 * time.Second,
		GRPCKeepaliveTimeout:   10 * time.Second,
		GRPCMaxMessageBytes:    64 << 20,
		ReconnectMinBackoff:    time.Second,
		ReconnectMaxBackoff:    30 * time.Second,
		CacheRestoreInterval:   2 * time.Second,
		CacheRestoreMaxBackoff: time.Minute,
		CacheWriteTimeout:      3 * time.Second,
		CacheRetryInterval:     10 * time.Second,
		CacheResyncInterval:    5 * time.Minute,
	}
	if cfg != want {
		t.Fatalf("getUsageConfig() = %+v, want %+v", cfg, want)
	}
	want.Enabled = true
	if err := want.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestUsageConfigValidate(t *testing.T) {
	t.Setenv("USAGE_SYSTEM_ENABLED", "true")
	t.Setenv("USAGE_SYSTEM_GRPC_ADDR", "usage-system:9090")
	valid := getUsageConfig()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*UsageConfig)
	}{
		{name: "address without port", mutate: func(u *UsageConfig) { u.GRPCAddr = "usage-system" }},
		{name: "address as a URL", mutate: func(u *UsageConfig) { u.GRPCAddr = "https://usage-system:9090" }},
		{name: "zero keepalive", mutate: func(u *UsageConfig) { u.GRPCKeepaliveTime = 0 }},
		{name: "keepalive under gRPC's floor", mutate: func(u *UsageConfig) { u.GRPCKeepaliveTime = 5 * time.Second }},
		{name: "zero retry interval", mutate: func(u *UsageConfig) { u.CacheRetryInterval = 0 }},
		{name: "zero resync interval", mutate: func(u *UsageConfig) { u.CacheResyncInterval = 0 }},
		{name: "negative ready timeout", mutate: func(u *UsageConfig) { u.ReadyTimeout = -time.Second }},
		{name: "min backoff above max", mutate: func(u *UsageConfig) { u.ReconnectMinBackoff = time.Hour }},
		{name: "restore interval above max", mutate: func(u *UsageConfig) { u.CacheRestoreInterval = time.Hour }},
		{name: "zero write timeout", mutate: func(u *UsageConfig) { u.CacheWriteTimeout = 0 }},
		{name: "zero message size", mutate: func(u *UsageConfig) { u.GRPCMaxMessageBytes = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			if err := cfg.Validate(); !stderrors.Is(err, errors.ErrInvalidConfig) {
				t.Fatalf("Validate() = %v, want ErrInvalidConfig", err)
			}
			cfg.Enabled = false
			if err := cfg.Validate(); err != nil {
				t.Fatalf("a disabled Usage System is never validated: %v", err)
			}
		})
	}
}

func TestConfigSyncMaxRecvBytes(t *testing.T) {
	if got := getConfigSyncConfig().MaxRecvBytes(); got != 64<<20 {
		t.Fatalf("default = %d, want 64 MiB", got)
	}
	if got := (ConfigSyncConfig{}).MaxRecvBytes(); got != defaultUsageGRPCMaxMessageBytes {
		t.Fatalf("unset = %d, want the control plane's default usage message limit", got)
	}
	t.Setenv("CONFIG_SYNC_GRPC_MAX_RECV_BYTES", "134217728")
	if got := getConfigSyncConfig().MaxRecvBytes(); got != 128<<20 {
		t.Fatalf("from env = %d, want %d", got, 128<<20)
	}

	valid := ConfigSyncConfig{
		DataPlaneEnabled: true,
		Token:            "token",
		GRPCEndpoint:     "control-plane:9443",
		LKGPath:          "/tmp/lkg",
		LKGKey:           base64.StdEncoding.EncodeToString(make([]byte, configSyncKeyBytes)),
		PollInterval:     time.Second,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("zero takes the default: %v", err)
	}
	for _, bad := range []int{-1, 1 << 20, 64<<20 - 1} {
		valid.GRPCMaxRecvBytes = bad
		if err := valid.Validate(); !stderrors.Is(err, errors.ErrInvalidConfig) {
			t.Fatalf("%d is below the floor: Validate() = %v", bad, err)
		}
	}
}
