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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

func secretStoresEnv(t *testing.T) {
	t.Helper()
	minimumEnv(t)
	for _, key := range []string{
		"SECRET_STORES_ENABLED", "SECRET_STORES_GATEWAYS", "SECRET_STORES_FILE",
		"SECRET_STORES_FETCH_TIMEOUT", "SECRET_STORES_REFRESH_INTERVAL",
		"SECRET_STORES_PROBE_INTERVAL", "SECRET_STORES_READINESS_GATE",
		"INSTANCE_DEPLOYMENT_TYPE",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadConfig_SecretStoresDefaults(t *testing.T) {
	secretStoresEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := SecretStoresConfig{
		Gateways:        secretstore.EligibilityHybrid,
		FetchTimeout:    2 * time.Second,
		RefreshInterval: 15 * time.Second,
		ProbeInterval:   60 * time.Second,
	}
	if cfg.SecretStores != want {
		t.Fatalf("SecretStores = %+v, want %+v", cfg.SecretStores, want)
	}
}

func TestLoadConfig_SecretStoresEnabledWithoutFile(t *testing.T) {
	secretStoresEnv(t)
	t.Setenv("SECRET_STORES_ENABLED", "true")
	t.Setenv("INSTANCE_DEPLOYMENT_TYPE", InstanceDeploymentSaaS)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("NeuralTrust's admin runs enabled with no store file: %v", err)
	}
	if !cfg.SecretStores.Enabled || cfg.SecretStores.File != "" {
		t.Fatalf("SecretStores = %+v", cfg.SecretStores)
	}
}

func TestLoadConfig_SecretStoresGateways(t *testing.T) {
	for in, want := range map[string]secretstore.Eligibility{
		"hybrid": secretstore.EligibilityHybrid,
		" ALL ":  secretstore.EligibilityAll,
	} {
		t.Run(in, func(t *testing.T) {
			secretStoresEnv(t)
			t.Setenv("SECRET_STORES_GATEWAYS", in)
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if cfg.SecretStores.Gateways != want {
				t.Fatalf("Gateways = %q, want %q", cfg.SecretStores.Gateways, want)
			}
		})
	}
}

func TestLoadConfig_SecretStoresRejects(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secret-stores.yaml")
	tests := []struct {
		name    string
		env     map[string]string
		mention string
	}{
		{
			name:    "unknown eligibility",
			env:     map[string]string{"SECRET_STORES_GATEWAYS": "hosted"},
			mention: "SECRET_STORES_GATEWAYS",
		},
		{
			name:    "store file on a saas plane, flag off",
			env:     map[string]string{"SECRET_STORES_FILE": file, "INSTANCE_DEPLOYMENT_TYPE": "saas"},
			mention: "SECRET_STORES_FILE",
		},
		{
			name:    "store file on a saas plane, flag on",
			env:     map[string]string{"SECRET_STORES_ENABLED": "true", "SECRET_STORES_FILE": file, "INSTANCE_DEPLOYMENT_TYPE": "SaaS"},
			mention: "SECRET_STORES_FILE",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretStoresEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			_, err := LoadConfig()
			if !stderrors.Is(err, errors.ErrInvalidConfig) || !strings.Contains(err.Error(), tt.mention) {
				t.Fatalf("LoadConfig() = %v, want ErrInvalidConfig naming %s", err, tt.mention)
			}
		})
	}
}

func TestLoadConfig_SecretStoresFileOnSelfHostedPlane(t *testing.T) {
	secretStoresEnv(t)
	t.Setenv("SECRET_STORES_ENABLED", "true")
	t.Setenv("SECRET_STORES_GATEWAYS", "all")
	t.Setenv("SECRET_STORES_FILE", " /etc/trustgate/secret-stores.yaml ")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SecretStores.File != "/etc/trustgate/secret-stores.yaml" {
		t.Fatalf("File = %q", cfg.SecretStores.File)
	}
}

// TestSaaSOverlaysKeepSecretStoresOff checks NeuralTrust's own overlays: they
// must declare saas, so a store file would refuse to boot, ship no store
// file, and leave only hybrid gateways eligible.
func TestSaaSOverlaysKeepSecretStoresOff(t *testing.T) {
	overlays, err := filepath.Glob(filepath.Join("..", "..", "k8s", "overlays", "*", "config.env"))
	if err != nil || len(overlays) == 0 {
		t.Fatalf("no overlay config.env found (err=%v)", err)
	}
	for _, path := range overlays {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			t.Setenv("INSTANCE_DEPLOYMENT_TYPE", "")
			t.Setenv("SECRET_STORES_FILE", "")
			t.Setenv("SECRET_STORES_GATEWAYS", "")
			loadOverlayEnv(t, path)

			if got := getConfigSyncConfig().DeploymentType; got != InstanceDeploymentSaaS {
				t.Errorf("INSTANCE_DEPLOYMENT_TYPE = %q, want %q", got, InstanceDeploymentSaaS)
			}
			s, err := getSecretStoresConfig()
			if err != nil {
				t.Fatalf("overlay secret stores config: %v", err)
			}
			if s.File != "" {
				t.Error("a NeuralTrust overlay sets SECRET_STORES_FILE")
			}
			if s.Gateways != secretstore.EligibilityHybrid {
				t.Errorf("SECRET_STORES_GATEWAYS = %q, want hybrid", s.Gateways)
			}
		})
	}
}

func TestValidateSecretStoresDurations(t *testing.T) {
	c := &Config{SecretStores: SecretStoresConfig{Enabled: true, FetchTimeout: time.Second, RefreshInterval: time.Second}}
	err := c.validateSecretStores()
	if !stderrors.Is(err, errors.ErrInvalidConfig) || !strings.Contains(err.Error(), "SECRET_STORES_PROBE_INTERVAL") {
		t.Fatalf("validateSecretStores() = %v, want SECRET_STORES_PROBE_INTERVAL refused", err)
	}
	c.SecretStores.Enabled = false
	if err := c.validateSecretStores(); err != nil {
		t.Fatalf("a disabled, hand-built config must validate: %v", err)
	}
}
