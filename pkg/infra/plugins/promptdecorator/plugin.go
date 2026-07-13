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

package promptdecorator

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

const PluginName = "prompt_decorator"

const (
	sourceFormatOpenAI    = "openai"
	sourceFormatAnthropic = "anthropic"

	decisionDecorated   = "decorated"
	decisionNoOp        = "no_op"
	decisionObserved    = "observed"
	decisionParseError  = "parse_error"
	decisionRejected    = "rejected"
	decisionUnsupported = "unsupported_source_format"

	typeSystemMessageRequired = "system_message_required"
	typeInvalidRequestBody    = "invalid_request_body"
	typeUnsupportedSource     = "unsupported_source_format"
)

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct{}

type promptDecoratorData struct {
	Decision              string `json:"decision"`
	SourceFormat          string `json:"source_format,omitempty"`
	DecoratorCount        int    `json:"decorator_count,omitempty"`
	RequireSystemMessage  bool   `json:"require_system_message,omitempty"`
	OriginalSystemMessage bool   `json:"original_system_message,omitempty"`
	WouldDecorate         bool   `json:"would_decorate,omitempty"`
	WouldReject           bool   `json:"would_reject,omitempty"`
	ParseError            bool   `json:"parse_error,omitempty"`
	ErrorType             string `json:"error_type,omitempty"`
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Name() string {
	return PluginName
}

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) MutatesRequestBody() bool {
	return true
}

func (p *Plugin) MutatesResponseBody() bool {
	return false
}

func (p *Plugin) MutatesMetadata() bool {
	return false
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Stage != policy.StagePreRequest || in.Request == nil {
		return okResult(), nil
	}

	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("prompt_decorator: %w", err)
	}

	data := promptDecoratorData{
		SourceFormat:         in.Request.SourceFormat,
		DecoratorCount:       len(cfg.Decorators),
		RequireSystemMessage: cfg.RequireSystemMessage,
	}
	if !supportedSourceFormat(in.Request.SourceFormat) {
		if cfg.RequireSystemMessage && appplugins.Blocks(in.Mode) {
			data.Decision = decisionRejected
			data.ErrorType = typeUnsupportedSource
			setExecutionData(in.Event, in.Mode, data)
			return nil, bodyFreeRequestError(typeUnsupportedSource)
		}
		data.Decision = decisionUnsupported
		data.WouldReject = cfg.RequireSystemMessage
		setExecutionData(in.Event, in.Mode, data)
		return okResult(), nil
	}

	if cfg.RequireSystemMessage {
		data.OriginalSystemMessage, err = hasOriginalSystem(in.Request.SourceFormat, in.Request.OriginalBody)
		if err != nil {
			if !appplugins.Blocks(in.Mode) {
				data.Decision = decisionParseError
				data.ParseError = true
				setExecutionData(in.Event, in.Mode, data)
				return okResult(), nil
			}
			data.Decision = decisionRejected
			data.ErrorType = typeInvalidRequestBody
			setExecutionData(in.Event, in.Mode, data)
			return nil, bodyFreeRequestError(typeInvalidRequestBody)
		}
		if !data.OriginalSystemMessage {
			if !appplugins.Blocks(in.Mode) {
				data.Decision = decisionObserved
				data.WouldReject = true
				setExecutionData(in.Event, in.Mode, data)
				return okResult(), nil
			}
			data.Decision = decisionRejected
			data.ErrorType = typeSystemMessageRequired
			setExecutionData(in.Event, in.Mode, data)
			return nil, systemMessageRequiredError()
		}
	}

	if len(cfg.Decorators) == 0 {
		data.Decision = decisionNoOp
		setExecutionData(in.Event, in.Mode, data)
		return okResult(), nil
	}

	enforce := appplugins.Blocks(in.Mode)
	requestBody, changed, err := transformBody(in.Request.SourceFormat, in.Request.Body, cfg.Decorators, enforce)
	if err != nil {
		if !enforce {
			data.Decision = decisionParseError
			data.ParseError = true
			setExecutionData(in.Event, in.Mode, data)
			return okResult(), nil
		}
		data.Decision = decisionRejected
		data.ErrorType = typeInvalidRequestBody
		setExecutionData(in.Event, in.Mode, data)
		return nil, bodyFreeRequestError(typeInvalidRequestBody)
	}
	if !enforce {
		data.Decision = decisionObserved
		data.WouldDecorate = changed
		setExecutionData(in.Event, in.Mode, data)
		return okResult(), nil
	}
	if !changed {
		data.Decision = decisionNoOp
		setExecutionData(in.Event, in.Mode, data)
		return okResult(), nil
	}

	data.Decision = decisionDecorated
	setExecutionData(in.Event, in.Mode, data)
	return &appplugins.Result{
		StatusCode:  http.StatusOK,
		RequestBody: requestBody,
	}, nil
}

func supportedSourceFormat(sourceFormat string) bool {
	return sourceFormat == sourceFormatOpenAI || sourceFormat == sourceFormatAnthropic
}

func hasOriginalSystem(sourceFormat string, body []byte) (bool, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return false, nil
	}
	switch sourceFormat {
	case sourceFormatOpenAI:
		return hasOpenAIOriginalSystem(body)
	case sourceFormatAnthropic:
		return hasAnthropicOriginalSystem(body)
	default:
		return false, nil
	}
}

func transformBody(sourceFormat string, body []byte, decorators []decorator, marshalOutput bool) ([]byte, bool, error) {
	switch sourceFormat {
	case sourceFormatOpenAI:
		return transformOpenAIBody(body, decorators, marshalOutput)
	case sourceFormatAnthropic:
		return transformAnthropicBody(body, decorators, marshalOutput)
	default:
		return nil, false, nil
	}
}

func systemMessageRequiredError() error {
	return &appplugins.PluginError{
		StatusCode: http.StatusBadRequest,
		Type:       typeSystemMessageRequired,
		Message:    "system message required",
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"error":{"type":"system_message_required"}}`),
	}
}

func bodyFreeRequestError(errorType string) error {
	return &appplugins.PluginError{
		StatusCode: http.StatusBadRequest,
		Type:       errorType,
		Message:    errorType,
	}
}

func setExecutionData(event *metrics.EventContext, mode policy.Mode, data promptDecoratorData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
	if mode == policy.ModeObserve {
		appplugins.SetDecision(event, mode)
		return
	}
	switch data.Decision {
	case decisionRejected:
		appplugins.SetDecision(event, mode)
	default:
		appplugins.SetDecisionFromOutcome(event, "allowed")
	}
}

func okResult() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
