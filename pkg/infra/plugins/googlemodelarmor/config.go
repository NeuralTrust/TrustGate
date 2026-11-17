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
	"math"
	"regexp"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
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
// MaxAccumulatedBytes is maxSanitizeBytes, which together with the correlation
// prompt stays within Model Armor's documented screening limit of 65,536 tokens
// for the prompt injection, Responsible AI and CSAM filters. Past it a filter
// answers EXECUTION_SKIPPED.
// https://docs.cloud.google.com/model-armor/quotas
var streamingDefaults = pluginutil.StreamingDefaults{
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
	// FailureMode is what a request costs when Model Armor cannot evaluate it
	// (unreachable, too slow, credentials refused, a block_on filter that
	// returned no verdict): "open" (the default) lets it through, "closed"
	// blocks it in a mode that blocks and records it in observe. Content Model
	// Armor cannot inspect (an input failure) is refused in a blocking mode
	// either way. Under closed, a block_on filter the template does not enable
	// refuses every request (filter_not_in_template).
	FailureMode string `mapstructure:"failure_mode"`
	// TimeoutFailureMode is what a request costs when Model Armor does not
	// answer within TimeoutSeconds ("open" or "closed"). Empty follows
	// FailureMode, so a policy that only sets failure_mode keeps treating a
	// timeout as any other availability failure.
	TimeoutFailureMode string `mapstructure:"timeout_failure_mode"`
	// TimeoutSeconds caps each call to Model Armor, token minting included.
	// Zero uses the gateway default (MODEL_ARMOR_TIMEOUT). It applies to the
	// buffered legs; a streamed block keeps its fixed per-block limit.
	TimeoutSeconds int `mapstructure:"timeout_seconds"`
	// Streaming tunes the per-block inspection of the pre_response leg.
	Streaming pluginutil.StreamingSettings `mapstructure:"streaming"`
}

func parseConfig(settings map[string]any) (Settings, error) {
	if err := wholeSeconds(settings); err != nil {
		return Settings{}, err
	}
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
	if s.FailureMode == "" {
		s.FailureMode = pluginutil.DefaultFailureMode
	}
	if s.TimeoutFailureMode == "" {
		s.TimeoutFailureMode = s.FailureMode
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
	if err := pluginutil.ValidateFailureMode(PluginName, s.FailureMode); err != nil {
		return err
	}
	switch s.TimeoutFailureMode {
	case pluginutil.FailureModeOpen, pluginutil.FailureModeClosed:
	default:
		return fmt.Errorf("google_model_armor: timeout_failure_mode must be one of open, closed")
	}
	if s.TimeoutSeconds < 0 || s.TimeoutSeconds > maxTimeoutSeconds {
		return fmt.Errorf("google_model_armor: timeout_seconds must be between 1 and %d, or empty for the gateway default", maxTimeoutSeconds)
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

// maxTimeoutSeconds bounds timeout_seconds. It may exceed the gateway default:
// a policy that would rather wait than fail can ask for it.
const maxTimeoutSeconds = 60

const (
	settingTimeoutFailureMode = "timeout_failure_mode"
	settingTimeoutSeconds     = "timeout_seconds"
)

func (s Settings) callTimeout(gatewayDefault time.Duration) time.Duration {
	if s.TimeoutSeconds > 0 {
		return time.Duration(s.TimeoutSeconds) * time.Second
	}
	return gatewayDefault
}

// failClosedFor reports whether this policy refuses a failure with this
// detail: timeout_failure_mode decides a timeout, failure_mode every other
// failure.
func (s Settings) failClosedFor(detail string) bool {
	if detail == appplugins.DetailTimeout {
		return s.TimeoutFailureMode == pluginutil.FailureModeClosed
	}
	return s.FailureMode == pluginutil.FailureModeClosed
}

func (s Settings) mayFailClosed() bool {
	return s.failClosedFor("") || s.failClosedFor(appplugins.DetailTimeout)
}

// keepsMaskOnGap reports whether a usable mask is applied in this mode although
// some content went without a verdict for an availability reason (a block_on
// filter the template never enabled, a chunk Model Armor did not answer). It is
// the one place that rule lives: a mode that blocks keeps the mask, since the
// de-identified text is already in hand and releasing the original would send
// the raw data, unless the policy fails closed on that failure, which refuses
// what was not evaluated instead.
func (s Settings) keepsMaskOnGap(mode policy.Mode, detail string) bool {
	return appplugins.Blocks(mode) && !s.failClosedFor(detail)
}

// failClosedOf reports whether a policy with these settings refuses a failure
// with this detail, reading the modes leniently when the settings do not parse.
func failClosedOf(settings map[string]any, detail string) bool {
	if cfg, err := parseConfig(settings); err == nil {
		return cfg.failClosedFor(detail)
	}
	return failClosedFromRaw(settings, detail)
}

func mayFailClosedOf(settings map[string]any) bool {
	return failClosedOf(settings, "") || failClosedOf(settings, appplugins.DetailTimeout)
}

// failClosedFromRaw reads the mode that decides a failure with this detail
// straight from settings that do not parse. A timeout reads
// timeout_failure_mode when it is a non-empty string and falls back to
// failure_mode, as applyDefaults does.
func failClosedFromRaw(settings map[string]any, detail string) bool {
	if detail == appplugins.DetailTimeout {
		if mode, ok := rawString(settings, settingTimeoutFailureMode); ok {
			return strings.EqualFold(mode, pluginutil.FailureModeClosed)
		}
	}
	return pluginutil.FailClosedFromRaw(settings)
}

// wholeSeconds rejects a fractional timeout_seconds, which decoding into an int
// would otherwise truncate (0.5 would silently become the gateway default).
func wholeSeconds(settings map[string]any) error {
	for k, v := range settings {
		if !strings.EqualFold(k, settingTimeoutSeconds) {
			continue
		}
		var f float64
		switch n := v.(type) {
		case float64:
			f = n
		case float32:
			f = float64(n)
		case bool:
			return fmt.Errorf("google_model_armor: timeout_seconds must be a whole number of seconds")
		default:
			continue
		}
		if f != math.Trunc(f) {
			return fmt.Errorf("google_model_armor: timeout_seconds must be a whole number of seconds")
		}
	}
	return nil
}

func rawString(settings map[string]any, key string) (string, bool) {
	for k, v := range settings {
		if !strings.EqualFold(k, key) {
			continue
		}
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s), true
		}
	}
	return "", false
}
