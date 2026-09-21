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

// Credentials selects how the plugin authenticates to Model Armor for one
// policy, nested under a `credentials` key in settings and shaped after
// bedrock_guardrail's own Credentials struct. Application Default Credentials
// alone means every policy on a gateway calls Model Armor as the same pod
// identity — fine self-hosted, unworkable multi-tenant, since our one
// identity would then need a grant on every customer's GCP project.
// Precedence, most specific first:
//
//  1. ImpersonateServiceAccount set: impersonate that service account by
//     email through GCP's IAM Credentials API. This is the keyless path to
//     lead with: the customer creates a service account in their own
//     project, grants it roles/modelarmor.user, and grants our ambient
//     identity roles/iam.serviceAccountTokenCreator on it. An email is not a
//     credential — useless without their grant, and revocable without
//     touching our database.
//  2. ServiceAccountJSON set: mint tokens from that explicit service-account
//     key. Like bedrock_guardrail's own access_key_id/secret_access_key,
//     policy settings persist through a bare json.Marshal with no encryption
//     in the repository layer, so this sits there in plaintext next to
//     bedrock's secret_access_key. That is a known, separate decision
//     (RUN-1644), not an oversight here.
//  3. Neither set: Application Default Credentials / GKE Workload Identity —
//     today's only behaviour, unchanged, so a policy with no credentials
//     block keeps working exactly as before.
type Credentials struct {
	ImpersonateServiceAccount string `mapstructure:"impersonate_service_account"`
	ServiceAccountJSON        string `mapstructure:"service_account_json"` // #nosec G101 -- config field name, not a credential
}

// Settings configures the google_model_armor plugin.
type Settings struct {
	Project     string      `mapstructure:"project"`
	Location    string      `mapstructure:"location"`
	Template    string      `mapstructure:"template"`
	BlockOn     []string    `mapstructure:"block_on"`
	SDPAction   string      `mapstructure:"sdp_action"`
	Message     string      `mapstructure:"message"`
	Credentials Credentials `mapstructure:"credentials"`
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
	if strings.TrimSpace(s.Credentials.ImpersonateServiceAccount) != "" &&
		strings.TrimSpace(s.Credentials.ServiceAccountJSON) != "" {
		return fmt.Errorf(
			"google_model_armor: credentials: set only one of impersonate_service_account or service_account_json",
		)
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
