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
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// prepareAnthropicConverse finishes an Anthropic Messages request translated
// to Converse once the model is known. It logs what Converse cannot express
// and keeps the Anthropic-only fields away from a model of another family. On
// a fallback leg those fields are dropped instead, so the fallback still
// serves the call.
func (p *providerInvoker) prepareAnthropicConverse(ctx context.Context, req *infracontext.RequestContext, body []byte, model string) ([]byte, error) {
	if p.logger.Enabled(ctx, slog.LevelDebug) {
		if unmapped := adapter.AnthropicKeysUnmappedOnConverse(req.Body); len(unmapped) > 0 {
			p.logger.Debug("anthropic request fields not sent to bedrock",
				slog.String("model", model),
				slog.String("fields", strings.Join(unmapped, ",")))
		}
	}
	out, dropped, err := adapter.GateAnthropicConverseFields(body, model, req.FallbackLeg)
	if err != nil {
		var unsupported *adapter.AnthropicFieldsUnsupportedError
		if errors.As(err, &unsupported) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRequestPayload, err)
		}
		return nil, fmt.Errorf("adapt request (anthropic->bedrock): %w", err)
	}
	if len(dropped) > 0 {
		p.logger.Info("anthropic-only fields dropped on bedrock fallback",
			slog.String("model", model),
			slog.String("fields", strings.Join(dropped, ",")))
	}
	return out, nil
}
