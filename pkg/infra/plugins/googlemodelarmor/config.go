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
	"regexp"
	"strings"
	"time"

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
//     touching our database. Refused unless the gateway sets
//     MODEL_ARMOR_ALLOW_AMBIENT_IDENTITY: the impersonating identity is the
//     pod's, shared by every tenant, so a tenant naming any service account
//     is a confused deputy (see Plugin.checkIdentity).
//  2. ServiceAccountJSON set: mint tokens from that explicit service-account
//     key. Policy settings are persisted unencrypted, but the policy API masks
//     this field in every response (see CredentialPaths); encryption at rest
//     is tracked separately.
//  3. Neither set: Application Default Credentials / GKE Workload Identity —
//     the pod identity, refused unless MODEL_ARMOR_ALLOW_AMBIENT_IDENTITY is
//     set, for the same reason as path 1.
type Credentials struct {
	ImpersonateServiceAccount string `mapstructure:"impersonate_service_account"`
	ServiceAccountJSON        string `mapstructure:"service_account_json"` // #nosec G101 -- config field name, not a credential
}

// Settings configures the google_model_armor plugin.
// Streaming defaults. A sanitize call runs every filter in the template
// against the text, so it is closer to bedrock's guardrail than to a single
// classifier and the block loop calls it at the same cadence.
//
// It is on by default: a guardrail that silently stops guarding the moment a
// client sets stream: true is not a guardrail. A policy opts out with
// streaming.enabled: false.
//
// MaxAccumulatedBytes is maxSanitizeBytes, which together with the correlation
// prompt stays within Model Armor's documented screening limit of 65,536 tokens
// for the prompt injection, Responsible AI and CSAM filters. Past it a filter
// answers EXECUTION_SKIPPED.
// https://docs.cloud.google.com/model-armor/quotas
var streamingDefaults = pluginutil.StreamingDefaults{
	EnabledByDefault:     true,
	HeadChars:            400,
	MinCharsBetweenEvals: 2048,
	MaxHoldMS:            800,
	MaxAccumulatedBytes:  maxSanitizeBytes,
	GuardTimeout:         2 * time.Second,
}

// maxSanitizeBytes caps one sanitize call's text: the streaming window and a
// buffered chunk. Model Armor screens at most 65,536 tokens and skips a filter
// above that, which this plugin counts as a filter that did not run. The limit
// is Google's and cannot be raised. About 262,144 characters of English fit in
// 65,536 tokens, but code and most other languages take more tokens per byte,
// and a token covers at least one byte (an assumption: Google does not document
// it). The call also carries the correlation prompt of a response, at most
// maxCorrelationPromptBytes (8 KiB), and counts against the same limit, so the
// text is 65,536 minus that: 57,344 bytes. A stream block whose own new text
// exceeds the window is split by the stream executor.
const maxSanitizeBytes = 57344

type Settings struct {
	Project     string      `mapstructure:"project"`
	Location    string      `mapstructure:"location"`
	Template    string      `mapstructure:"template"`
	BlockOn     []string    `mapstructure:"block_on"`
	SDPAction   string      `mapstructure:"sdp_action"`
	Message     string      `mapstructure:"message"`
	Credentials Credentials `mapstructure:"credentials"`
	// Streaming tunes the per-block inspection of the pre_response leg. It is on
	// when the block is absent; streaming.enabled: false opts out.
	Streaming pluginutil.StreamingSettings `mapstructure:"streaming"`
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
	s.Streaming.ApplyDefaults(streamingDefaults)
}

var (
	// locationPattern is a GCP region (us-central1, europe-west4) or a Model Armor
	// multi-region (us, eu). It has no dot,
	// slash, colon, '#', '@' or '?', so it cannot change the host it is put in.
	locationPattern = regexp.MustCompile(`^[a-z]+(-[a-z]+)*[0-9]*$`)
	// projectPattern is a project id (lowercase letters, digits, hyphens, up to
	// 30 characters) or a numeric project number. Legacy domain-scoped ids
	// ("example.com:proj") are not accepted: the colon and dot are path-unsafe.
	projectPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$`)
	// templatePattern is a Model Armor template id.
	templatePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
)

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
	// project, location and template are interpolated into the request URL, and
	// location into the HOST. The request carries a cloud-platform bearer token
	// (the policy's own, or the gateway pod's ambient identity), so a value that
	// can change the host or the path is a token leak, not a typo.
	if !locationPattern.MatchString(s.Location) {
		return fmt.Errorf("google_model_armor: location must be a GCP region or multi-region such as us-central1 or eu")
	}
	if !projectPattern.MatchString(s.Project) {
		return fmt.Errorf("google_model_armor: project must be a GCP project id or number")
	}
	if !templatePattern.MatchString(s.Template) {
		return fmt.Errorf("google_model_armor: template must contain only letters, digits, hyphens and underscores")
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
	return s.Streaming.Validate(PluginName)
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

// RetiredSettings lists the settings keys this policy never stores: the plugin
// ignores them, so a stored value would read as behaviour the policy does not
// have.
func (p *Plugin) RetiredSettings() []string {
	return []string{
		pluginutil.SettingOnError, pluginutil.SettingOnMaskFailure,
		pluginutil.SettingStreamingOnError, pluginutil.SettingStreamingGuardTimeout,
	}
}
