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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigOriginalClientIP(t *testing.T) {
	for _, tc := range []struct {
		name, mode, prefixes string
		invalid              bool
	}{
		{"peer default", "peer", "", false},
		{"gcp configured", "gcp", "10.129.0.0/23,130.211.0.0/22", false},
		{"gcp requires trust", "gcp", "", true},
		{"invalid mode", "automatic", "10.129.0.0/23", true},
		{"invalid prefix", "gcp", "bad", true},
		{"cannot trust all ipv4", "gcp", "0.0.0.0/0", true},
		{"cannot trust all ipv6", "gcp", "::/0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			minimumEnv(t)
			t.Setenv("ORIGINAL_REQUEST_IP_MODE", tc.mode)
			t.Setenv("ORIGINAL_REQUEST_TRUSTED_PROXY_CIDRS", tc.prefixes)
			cfg, err := LoadConfig()
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.mode, cfg.ClientIP.Mode)
			if tc.mode == "gcp" {
				require.Len(t, cfg.ClientIP.TrustedProxyCIDRs, 2)
			}
		})
	}
}
