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
	"sort"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "azure_content_safety"

const (
	decisionBlocked  = "blocked"
	decisionReported = "reported"
	decisionAllowed  = "allowed"
)

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
// category not requested in categories. This cannot live in parseConfig (run
// via ValidateConfig on every load): a policy saved before this rule existed
// would turn into a run-time config_invalid failure the moment it did.
// Execute instead requests the union of categories and category_severity's
// keys (Settings.requestCategories) so an already-saved mismatched policy
// keeps working; this only stops a new one from being saved with the same
// gap.
//
// previous (the settings stored before this write) is unused here: this
// plugin's rule is a same-settings internal consistency check, not one that
// depends on what changed.
func (p *Plugin) ValidateSettingsWrite(settings, _ map[string]any) error {
	cfg, err := parseConfig(settings)
	if err != nil {
		return err
	}
	if missing := cfg.unrequestedThresholds(); len(missing) > 0 {
		return fmt.Errorf(
			"azure_content_safety: category_severity key %q is not in categories", missing[0],
		)
	}
	return nil
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
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureDecodeFailed, "", err)
	}
	creq, decErr := p.registry.DecodeRequestFor(in.Request.Body, format)
	if decErr != nil {
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureDecodeFailed, "", decErr)
	}
	if creq == nil {
		return passThrough(), nil
	}
	text := joinRequestText(creq)
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}

	start := time.Now()
	resp, err := p.client.Analyze(ctx, cfg.Endpoint, cfg.APIKey, analyzeRequest{
		Text:       text,
		Categories: cfg.requestCategories(),
		OutputType: cfg.OutputType,
	})
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return p.externalFailure(ctx, in, cfg, latency, appplugins.FailureTransport, "", err)
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
// the shared appplugins.HandleExternalFailure: fail closed (502
// guardrail_unavailable) in a blocking mode, fail open (pass through) in
// observe, or always fail open for a decode_failed reason. It builds this
// plugin's own Data so the failure_reason/failure_detail pair travels with
// every other external guardrail's telemetry in the same shape.
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
		Ctx:    ctx,
		Plugin: PluginName,
		Stage:  in.Stage,
		Mode:   in.Mode,
		Reason: reason,
		Detail: detail,
		Err:    err,
		Logger: p.logger,
		Event:  in.Event,
	})
	setExtras(in.Event, &Data{
		Endpoint:      cfg.Endpoint,
		OutputType:    cfg.OutputType,
		Mode:          string(in.Mode),
		LatencyMS:     latencyMS,
		Decision:      outcome.Decision,
		FailureReason: string(reason),
		FailureDetail: detail,
	})
	return outcome.Result, outcome.Err
}

func joinRequestText(creq *adapter.CanonicalRequest) string {
	parts := make([]string, 0, len(creq.Messages)+1)
	if strings.TrimSpace(creq.System) != "" {
		parts = append(parts, creq.System)
	}
	for _, msg := range creq.Messages {
		if strings.TrimSpace(msg.Content) != "" {
			parts = append(parts, msg.Content)
		}
	}
	return strings.Join(parts, "\n")
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
