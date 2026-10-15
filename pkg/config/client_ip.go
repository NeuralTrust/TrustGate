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
	"net/netip"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

type ClientIPConfig struct {
	Mode              string
	TrustedProxyCIDRs []netip.Prefix
}

func getClientIPConfig() (ClientIPConfig, error) {
	mode := strings.ToLower(strings.TrimSpace(getEnv("ORIGINAL_REQUEST_IP_MODE", "peer")))
	if mode != "peer" && mode != "gcp" {
		return ClientIPConfig{}, fmt.Errorf("%w: ORIGINAL_REQUEST_IP_MODE must be peer or gcp", errors.ErrInvalidConfig)
	}
	prefixes, err := parsePrefixListEnv("ORIGINAL_REQUEST_TRUSTED_PROXY_CIDRS")
	if err != nil {
		return ClientIPConfig{}, err
	}
	if mode == "gcp" && len(prefixes) == 0 {
		return ClientIPConfig{}, fmt.Errorf("%w: gcp original request IP mode requires ORIGINAL_REQUEST_TRUSTED_PROXY_CIDRS", errors.ErrInvalidConfig)
	}
	return ClientIPConfig{Mode: mode, TrustedProxyCIDRs: prefixes}, nil
}
