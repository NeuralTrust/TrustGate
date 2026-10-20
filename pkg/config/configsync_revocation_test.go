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
	stderrors "errors"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func TestConfigSyncTokenRevocation_Defaults(t *testing.T) {
	t.Setenv("CONFIG_SYNC_TOKEN_REVOCATION_MODE", "")
	t.Setenv("CONFIG_SYNC_TOKEN_REVOCATION_REFRESH_INTERVAL", "")
	cs := getConfigSyncConfig()
	if got := cs.RevocationMode(); got != ConfigSyncTokenRevocationShadow {
		t.Fatalf("mode = %q, want shadow", got)
	}
	if got := cs.RevocationRefreshInterval(); got != 30*time.Second {
		t.Fatalf("interval = %s, want 30s", got)
	}
	if got := (ConfigSyncConfig{}).RevocationMode(); got != ConfigSyncTokenRevocationShadow {
		t.Fatalf("zero-value mode = %q, want shadow", got)
	}
}

func TestConfigSyncTokenRevocation_EnvIsNormalized(t *testing.T) {
	t.Setenv("CONFIG_SYNC_TOKEN_REVOCATION_MODE", " Enforce ")
	t.Setenv("CONFIG_SYNC_TOKEN_REVOCATION_REFRESH_INTERVAL", "45s")
	cs := getConfigSyncConfig()
	if cs.RevocationMode() != ConfigSyncTokenRevocationEnforce || cs.RevocationRefreshInterval() != 45*time.Second {
		t.Fatalf("got mode %q interval %s, want enforce and 45s", cs.RevocationMode(), cs.RevocationRefreshInterval())
	}
}

func TestConfigSyncTokenRevocation_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ConfigSyncConfig
		wantErr bool
	}{
		{"unset uses defaults", ConfigSyncConfig{}, false},
		{"off", ConfigSyncConfig{TokenRevocationMode: ConfigSyncTokenRevocationOff}, false},
		{"shadow", ConfigSyncConfig{TokenRevocationMode: ConfigSyncTokenRevocationShadow}, false},
		{"enforce", ConfigSyncConfig{TokenRevocationMode: ConfigSyncTokenRevocationEnforce}, false},
		{"unknown mode", ConfigSyncConfig{TokenRevocationMode: "strict"}, true},
		{"negative interval", ConfigSyncConfig{TokenRevocationRefreshInterval: -time.Second}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validateTokenRevocation()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateTokenRevocation() = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !stderrors.Is(err, errors.ErrInvalidConfig) {
				t.Fatalf("error %v is not ErrInvalidConfig", err)
			}
		})
	}
}
