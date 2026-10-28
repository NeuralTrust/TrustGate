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

package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// bedrockAnthropicBetas are the anthropic-beta flags Claude on Bedrock takes.
// Clients such as Claude Code also send flags only the Anthropic API knows,
// and Bedrock refuses a request that names one ("invalid beta flag").
var bedrockAnthropicBetas = map[string]struct{}{
	"computer-use-2025-01-24":                {},
	"token-efficient-tools-2025-02-19":       {},
	"interleaved-thinking-2025-05-14":        {},
	"output-128k-2025-02-19":                 {},
	"dev-full-thinking-2025-05-14":           {},
	"context-1m-2025-08-07":                  {},
	"context-management-2025-06-27":          {},
	"effort-2025-11-24":                      {},
	"tool-search-tool-2025-10-19":            {},
	"tool-examples-2025-10-29":               {},
	"fine-grained-tool-streaming-2025-05-14": {},
}

// anthropicConverse is what preparing an Anthropic request for Converse
// decided: the body to send, the beta flags to send with it, comma-joined,
// and whether the answer's reasoning streams as signed thinking blocks.
type anthropicConverse struct {
	body            []byte
	betas           string
	signedReasoning bool
}

// prepareAnthropicConverse finishes an Anthropic Messages request translated
// to Converse once the model is known. Reasoning (thinking, effort, the
// reasoning blocks of earlier turns, beta flags) goes on only when the
// registry forwards it and the model may be Claude, and beta flags only to a
// model ID that names Claude. It logs what Converse cannot express and keeps
// the Anthropic-only fields away from a model of another family; on a
// fallback leg those fields are dropped instead, so the fallback still serves
// the call.
func (p *providerInvoker) prepareAnthropicConverse(
	ctx context.Context,
	req *infracontext.RequestContext,
	options map[string]any,
	body []byte,
	model string,
) (anthropicConverse, error) {
	if p.logger.Enabled(ctx, slog.LevelDebug) {
		if unmapped := adapter.AnthropicKeysUnmappedOnConverse(req.Body); len(unmapped) > 0 {
			p.logger.Debug("anthropic request fields not sent to bedrock",
				slog.String("model", model),
				slog.String("fields", strings.Join(unmapped, ",")))
		}
	}
	vendor := adapter.BedrockModelVendor(model)
	bedrockOptions, err := providers.DecodeBedrockOptions(options)
	forward := err == nil && bedrockOptions.ForwardsReasoning()
	if !forward || (vendor != "" && vendor != "anthropic") {
		body, err = p.withoutReasoning(body, model, !forward)
		if err != nil {
			return anthropicConverse{}, err
		}
	}
	out, dropped, err := adapter.GateAnthropicConverseFields(body, model, req.FallbackLeg)
	if err != nil {
		var unsupported *adapter.AnthropicFieldsUnsupportedError
		if errors.As(err, &unsupported) {
			return anthropicConverse{}, fmt.Errorf("%w: %w", ErrInvalidRequestPayload, err)
		}
		return anthropicConverse{}, fmt.Errorf("adapt request (anthropic->bedrock): %w", err)
	}
	if len(dropped) > 0 {
		p.logger.Info("anthropic-only fields dropped on bedrock fallback",
			slog.String("model", model),
			slog.String("fields", strings.Join(dropped, ",")))
	}
	prepared := anthropicConverse{body: out, signedReasoning: forward}
	if forward && vendor == "anthropic" {
		prepared.betas = strings.Join(bedrockBetas(anthropicBetas(req)), ",")
	}
	return prepared, nil
}

// withoutReasoning drops the reasoning blocks of earlier turns and, when the
// registry does not forward reasoning, the thinking and effort options. The
// options still reach the family check, which refuses them for a model of
// another family on a routed leg.
func (p *providerInvoker) withoutReasoning(body []byte, model string, options bool) ([]byte, error) {
	out, stripped, err := adapter.StripConverseReasoningHistory(body)
	if err != nil {
		return nil, fmt.Errorf("adapt request (anthropic->bedrock): %w", err)
	}
	var dropped []string
	if options {
		if out, dropped, err = adapter.DropConverseAdditionalFields(out, adapter.ConverseReasoningFields...); err != nil {
			return nil, fmt.Errorf("adapt request (anthropic->bedrock): %w", err)
		}
	}
	if stripped || len(dropped) > 0 {
		p.logger.Debug("reasoning not sent to bedrock",
			slog.String("model", model),
			slog.Bool("history", stripped),
			slog.String("fields", strings.Join(dropped, ",")))
	}
	return out, nil
}

func bedrockBetas(joined string) []string {
	var out []string
	for _, flag := range strings.Split(joined, ",") {
		if _, ok := bedrockAnthropicBetas[strings.ToLower(flag)]; ok {
			out = append(out, flag)
		}
	}
	return out
}
