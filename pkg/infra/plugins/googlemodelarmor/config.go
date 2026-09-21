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

package googlemodelarmor

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	sdpActionBlock     = "block"
	sdpActionAnonymize = "anonymize"
)

const (
	filterSDP            = "sdp"
	filterRAI            = "rai"
	filterPIAndJailbreak = "pi_and_jailbreak"
	filterMaliciousURIs  = "malicious_uris"
	filterCSAM           = "csam"
)

// allFilters is the safe-by-default block_on set applied when a policy leaves
// block_on empty: every filter Model Armor's REST API can evaluate blocks by
// default, rather than the plugin silently allowing traffic through because
// nobody opted a category in.
var allFilters = []string{filterSDP, filterRAI, filterPIAndJailbreak, filterMaliciousURIs, filterCSAM}

// Settings configures the google_model_armor plugin. There is deliberately no
// service-account-JSON field: policy settings persist through a bare
// json.Marshal with no encryption in the repository layer, and a GCP service
// account key is an RSA private key that does not belong there. Authentication
// goes through pkg/infra/providers/gcpauth's Application Default Credentials /
// Workload Identity path instead.
type Settings struct {
	Project   string   `mapstructure:"project"`
	Location  string   `mapstructure:"location"`
	Template  string   `mapstructure:"template"`
	BlockOn   []string `mapstructure:"block_on"`
	SDPAction string   `mapstructure:"sdp_action"`
	Message   string   `mapstructure:"message"`
}

func parseConfig(settings map[string]any) (Settings, error) {
	cfg, err := pluginutil.Parse[Settings](settings)
	if err != nil {
		return Settings{}, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Settings{}, err
	}
	return cfg, nil
}

func (s *Settings) applyDefaults() {
	if len(s.BlockOn) == 0 {
		s.BlockOn = append([]string(nil), allFilters...)
	}
	if s.SDPAction == "" {
		s.SDPAction = sdpActionBlock
	}
}

func (s *Settings) validate() error {
	if strings.TrimSpace(s.Project) == "" {
		return fmt.Errorf("google_model_armor: project is required")
	}
	if strings.TrimSpace(s.Location) == "" {
		return fmt.Errorf("google_model_armor: location is required")
	}
	if strings.TrimSpace(s.Template) == "" {
		return fmt.Errorf("google_model_armor: template is required")
	}
	for _, f := range s.BlockOn {
		if !isValidFilter(f) {
			return fmt.Errorf("google_model_armor: block_on contains unknown filter %q", f)
		}
	}
	switch s.SDPAction {
	case sdpActionBlock, sdpActionAnonymize:
	default:
		return fmt.Errorf("google_model_armor: sdp_action must be one of block, anonymize")
	}
	return nil
}

func isValidFilter(f string) bool {
	switch f {
	case filterSDP, filterRAI, filterPIAndJailbreak, filterMaliciousURIs, filterCSAM:
		return true
	default:
		return false
	}
}

// blockOnSet returns block_on as a membership set for O(1) lookups during
// assessment.
func (s Settings) blockOnSet() map[string]bool {
	set := make(map[string]bool, len(s.BlockOn))
	for _, f := range s.BlockOn {
		set[f] = true
	}
	return set
}
