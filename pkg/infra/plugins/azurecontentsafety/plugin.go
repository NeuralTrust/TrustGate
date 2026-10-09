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

package azurecontentsafety

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "azure_content_safety"

const (
	decisionBlocked  = "blocked"
	decisionReported = "reported"
	decisionAllowed  = "allowed"
)

// maxTextCodePoints is the length text:analyze accepts for one text, counted in
// Unicode code points. A conversation above it is analysed over a window of its
// most recent content (windowOf) until it is split across calls; a last user
// message that alone exceeds it cannot be windowed and is the input's doing,
// not Azure's availability.
// https://learn.microsoft.com/en-us/azure/ai-services/content-safety/overview#input-requirements
const maxTextCodePoints = 10000

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
	client   *client
	logger   *slog.Logger
}

func New(registry *adapter.Registry, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry: registry,
		client:   newClient(),
		logger:   logger,
	}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) MutatesRequestBody() bool { return false }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

// ReadsContent opts into being sequenced after any same-priority rewriter, so
// the verdict is scored on the rewritten content (RUN-1693).
func (p *Plugin) ReadsContent() bool { return true }

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

var _ appplugins.SettingsWriteValidator = (*Plugin)(nil)

// ValidateSettingsWrite rejects a category_severity key that names a
// category not requested in categories, and an endpoint that does not carry the
// api-version query parameter. Neither can live in parseConfig (run via
// ValidateConfig on every load): a policy saved before the rule existed would
// turn into a run-time config_invalid failure the moment it did.
// Execute instead requests the union of categories and category_severity's
// keys (Settings.requestCategories) so an already-saved mismatched policy
// keeps working; this only stops a new one from being saved with the same
// gap. The api-version is checked only when the endpoint is new or changed, so
// editing any other setting of a stored policy is never refused for it.
func (p *Plugin) ValidateSettingsWrite(settings, previous map[string]any) error {
	cfg, err := parseConfig(settings)
	if err != nil {
		return err
	}
	if endpointChanged(cfg.Endpoint, previous) && !carriesAPIVersion(cfg.Endpoint) {
		return fmt.Errorf("azure_content_safety: endpoint must carry the api-version query parameter")
	}
	if missing := cfg.unrequestedThresholds(); len(missing) > 0 {
		return fmt.Errorf(
			"azure_content_safety: category_severity key %q is not in categories", missing[0],
		)
	}
	return nil
}

func endpointChanged(endpoint string, previous map[string]any) bool {
	before, ok := previous["endpoint"].(string)
	return !ok || before != endpoint
}

// carriesAPIVersion reports whether the endpoint's query names an api-version
// with a value; the parameter name is matched without regard to case.
func carriesAPIVersion(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	for key, values := range parsed.Query() {
		if !strings.EqualFold(key, "api-version") {
			continue
		}
		for _, v := range values {
			if v != "" {
				return true
			}
		}
	}
	return false
}

// CredentialPaths declares the settings paths that hold secrets, so the policy
// API masks them on read.
func (p *Plugin) CredentialPaths() []string {
	return []string{"api_key"}
}

// CredentialDestinations binds api_key to the endpoint it is sent to
// (Ocp-Apim-Subscription-Key on a request to cfg.Endpoint): changing the
// endpoint requires re-entering the key.
func (p *Plugin) CredentialDestinations() []string {
	return []string{"endpoint"}
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureConfigInvalid, "", err)
	}

	if in.Stage != policy.StagePreRequest {
		return passThrough(), nil
	}
	if in.Request == nil || p.registry == nil || in.Request.Provider == "" || len(in.Request.Body) == 0 {
		return passThrough(), nil
	}

	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat, err)
	}
	creq, decErr := p.registry.DecodeRequestFor(in.Request.Body, format)
	if decErr != nil {
		if pluginutil.SkipNonChatRoute(in.Event, string(in.Stage), in.Request.ProxyCapability, format) {
			return passThrough(), nil
		}
		if !adapter.IsRequestDecodeError(decErr) {
			return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat, decErr)
		}
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureDecodeFailed, "", decErr)
	}
	if creq == nil {
		return passThrough(), nil
	}
	window := windowOf(creq)
	if window.Text == "" && !window.LastUserTooLarge {
		return passThrough(), nil
	}
	if window.LastUserTooLarge {
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureInputTooLarge, appplugins.DetailPayloadTooLarge,
			fmt.Errorf("azure_content_safety: last user message exceeds the %d characters text:analyze accepts", maxTextCodePoints))
	}
	if strings.TrimSpace(window.Text) == "" {
		return passThrough(), nil
	}

	start := time.Now()
	resp, err := p.client.Analyze(ctx, cfg.Endpoint, cfg.APIKey, analyzeRequest{
		Text:       window.Text,
		Categories: cfg.requestCategories(),
		OutputType: cfg.OutputType,
	})
	latency := time.Since(start).Milliseconds()
	if err != nil {
		reason, detail := pluginutil.FailureOfError(err)
		return p.externalFailure(ctx, in, cfg, latency, reason, detail, err)
	}

	severities, breaches, missing := evaluate(resp, cfg)
	if len(breaches) == 0 && missing != "" {
		return p.externalFailure(ctx, in, cfg, latency, appplugins.FailureVerdictIncomplete, missing,
			fmt.Errorf("azure_content_safety: thresholded category %q missing from response", missing))
	}

	data := &Data{
		Endpoint:   cfg.Endpoint,
		OutputType: cfg.OutputType,
		Severities: severities,
		Mode:       string(in.Mode),
		LatencyMS:  latency,
	}
	if window.LeftOut > 0 {
		data.PartialWindow = true
		data.CharsNotInspected = window.LeftOut
	}

	if len(breaches) > 0 && appplugins.Blocks(in.Mode) {
		data.Decision = decisionBlocked
		data.Breached = breachedNames(breaches)
		setExtras(in.Event, data)
		recordScore(in.Event, breaches)
		appplugins.SetDecisionFromOutcome(in.Event, decisionBlocked)
		return nil, blockError(cfg.Message, breaches)
	}

	if len(breaches) > 0 {
		data.Decision = decisionReported
		data.Breached = breachedNames(breaches)
	} else {
		data.Decision = decisionAllowed
	}
	setExtras(in.Event, data)
	if len(breaches) > 0 {
		recordScore(in.Event, breaches)
	}
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
	return passThrough(), nil
}

// externalFailure turns a failed guardrail call into a plugin outcome via
// the shared appplugins.HandleExternalFailure, which owns the class and the
// mode: an availability failure passes through as failed_open, and an input
// failure is refused in a mode that blocks. It builds this plugin's own Data so
// failure_reason/failure_detail/failure_class travel with every other external
// guardrail's telemetry in the same shape.
func (p *Plugin) externalFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	latencyMS int64,
	reason appplugins.FailureReason,
	detail string,
	err error,
) (*appplugins.Result, error) {
	outcome := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
		Ctx:     ctx,
		Plugin:  PluginName,
		Stage:   in.Stage,
		Mode:    in.Mode,
		Reason:  reason,
		Detail:  detail,
		Message: cfg.Message,
		Err:     err,
		Logger:  p.logger,
		Event:   in.Event,
	})
	setExtras(in.Event, &Data{
		Endpoint:      cfg.Endpoint,
		OutputType:    cfg.OutputType,
		Mode:          string(in.Mode),
		LatencyMS:     latencyMS,
		Decision:      outcome.Decision,
		FailureReason: string(reason),
		FailureDetail: detail,
		FailureClass:  string(outcome.Class),
	})
	if outcome.Err != nil {
		return nil, outcome.Err
	}
	return outcome.Result, nil
}

// evaluate reports every breached category plus, when none breached, the
// first (sorted) thresholded category Azure's response said nothing about.
// requestCategories already asks Azure to analyze every category_severity
// key, so a category still missing from CategoriesAnalysis means Azure could
// not or did not evaluate it — a silent gap this call must not read as a
// clean pass.
func evaluate(resp *analyzeResponse, cfg Settings) (severities map[string]int, breaches []breachedCategory, missingThreshold string) {
	if resp == nil {
		return nil, nil, ""
	}
	severities = make(map[string]int, len(resp.CategoriesAnalysis))
	present := make(map[string]struct{}, len(resp.CategoriesAnalysis))
	for _, analysis := range resp.CategoriesAnalysis {
		severities[analysis.Category] = analysis.Severity
		present[analysis.Category] = struct{}{}
		threshold, ok := cfg.CategorySeverity[analysis.Category]
		if !ok {
			continue
		}
		if analysis.Severity >= threshold {
			breaches = append(breaches, breachedCategory{
				Category:  analysis.Category,
				Severity:  analysis.Severity,
				Threshold: threshold,
			})
		}
	}
	names := make([]string, 0, len(cfg.CategorySeverity))
	for c := range cfg.CategorySeverity {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		if _, ok := present[c]; !ok {
			missingThreshold = c
			break
		}
	}
	return severities, breaches, missingThreshold
}

func breachedNames(breaches []breachedCategory) []string {
	names := make([]string, 0, len(breaches))
	for _, breach := range breaches {
		names = append(names, breach.Category)
	}
	return names
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
