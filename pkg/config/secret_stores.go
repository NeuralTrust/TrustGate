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
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

const (
	defaultSecretStoresFetchTimeout    = 2 * time.Second
	defaultSecretStoresRefreshInterval = 15 * time.Second
	defaultSecretStoresProbeInterval   = 60 * time.Second
)

// SecretStoresConfig controls secret references: credential fields holding
// secret://store/path#field instead of a value, resolved by the planes that
// load a store file. Off by default, and off means no new reference is
// accepted and none is resolved.
type SecretStoresConfig struct {
	// Enabled is SECRET_STORES_ENABLED.
	Enabled bool
	// Gateways is SECRET_STORES_GATEWAYS, hybrid (the default) or all: which
	// gateways may hold references. Only installs where the customer runs
	// every plane set all.
	Gateways secretstore.Eligibility
	// File is SECRET_STORES_FILE, the store file a customer-operated plane
	// loads. NeuralTrust's own planes never set it.
	File string
	// FetchTimeout is SECRET_STORES_FETCH_TIMEOUT, per read from a store.
	FetchTimeout time.Duration
	// RefreshInterval is SECRET_STORES_REFRESH_INTERVAL, how often cached
	// values are checked for refresh.
	RefreshInterval time.Duration
	// ProbeInterval is SECRET_STORES_PROBE_INTERVAL, how often each store's
	// credentials are checked.
	ProbeInterval time.Duration
	// ReadinessGate is SECRET_STORES_READINESS_GATE: readiness waits until
	// every reference has resolved or failed for good.
	ReadinessGate bool
}

func getSecretStoresConfig() (SecretStoresConfig, error) {
	gateways, err := secretstore.ParseEligibility(getEnv("SECRET_STORES_GATEWAYS", ""))
	if err != nil {
		return SecretStoresConfig{}, fmt.Errorf("%w: SECRET_STORES_GATEWAYS must be %q or %q", errors.ErrInvalidConfig, secretstore.EligibilityHybrid, secretstore.EligibilityAll)
	}
	return SecretStoresConfig{
		Enabled:         getEnvBool("SECRET_STORES_ENABLED", false),
		Gateways:        gateways,
		File:            strings.TrimSpace(getEnv("SECRET_STORES_FILE", "")),
		FetchTimeout:    getEnvDuration("SECRET_STORES_FETCH_TIMEOUT", defaultSecretStoresFetchTimeout),
		RefreshInterval: getEnvDuration("SECRET_STORES_REFRESH_INTERVAL", defaultSecretStoresRefreshInterval),
		ProbeInterval:   getEnvDuration("SECRET_STORES_PROBE_INTERVAL", defaultSecretStoresProbeInterval),
		ReadinessGate:   getEnvBool("SECRET_STORES_READINESS_GATE", false),
	}, nil
}

// validateSecretStores refuses a store file on a plane that declares itself
// NeuralTrust's shared SaaS whatever SECRET_STORES_ENABLED says: on those
// planes the pod identity, environment and files are NeuralTrust's, and a
// tenant must never reach them through a reference.
func (c *Config) validateSecretStores() error {
	s := c.SecretStores
	if s.File != "" && c.ConfigSync.DeploymentType == InstanceDeploymentSaaS {
		return fmt.Errorf("%w: SECRET_STORES_FILE must not be set when INSTANCE_DEPLOYMENT_TYPE=%s", errors.ErrInvalidConfig, InstanceDeploymentSaaS)
	}
	if !s.Enabled {
		return nil
	}
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"SECRET_STORES_FETCH_TIMEOUT", s.FetchTimeout},
		{"SECRET_STORES_REFRESH_INTERVAL", s.RefreshInterval},
		{"SECRET_STORES_PROBE_INTERVAL", s.ProbeInterval},
	} {
		if d.value <= 0 {
			return fmt.Errorf("%w: %s must be positive", errors.ErrInvalidConfig, d.name)
		}
	}
	return nil
}
