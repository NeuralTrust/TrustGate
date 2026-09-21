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

package plugins

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// ErrPluginNotPreviewable is returned for a plugin that did not opt in via Previewable.
var ErrPluginNotPreviewable = errors.New("plugin: not previewable")

// previewTimeout bounds one preview run. A previewable plugin is pure and fast, so
// anything slower is a pathological configuration rather than work worth waiting for.
const previewTimeout = 5 * time.Second

// PreviewInput is a candidate policy configuration plus the sample request to run
// it against. It carries no gateway, consumer or scope: a preview answers what the
// plugin does to a body, not whether the policy would be selected for a request.
type PreviewInput struct {
	Slug     string
	Settings map[string]any
	Mode     policy.Mode
	Body     []byte
	Headers  map[string][]string
}

// PreviewDecision is what the plugin did to the sample request.
type PreviewDecision string

const (
	// PreviewRewritten means the plugin changed the body; RequestBody is what the model would receive.
	PreviewRewritten PreviewDecision = "rewritten"
	// PreviewUnchanged means the plugin ran and left the body alone.
	PreviewUnchanged PreviewDecision = "unchanged"
	// PreviewRejected means the plugin refused the request; Status, Type and Message say why.
	PreviewRejected PreviewDecision = "rejected"
)

// PreviewResult is the outcome of one preview run.
type PreviewResult struct {
	Decision    PreviewDecision
	RequestBody []byte
	Status      int
	Type        string
	Message     string
}

//go:generate mockery --name=PreviewService --dir=. --output=./mocks --filename=preview_service_mock.go --case=underscore --with-expecter
type PreviewService interface {
	Preview(ctx context.Context, in PreviewInput) (PreviewResult, error)
}

type previewService struct {
	registry Registry
}

// NewPreviewService builds the service that runs a previewable plugin against a sample request.
func NewPreviewService(registry Registry) PreviewService {
	return &previewService{registry: registry}
}

// Preview runs the plugin directly rather than through Executor.RunStage, which
// would need a StagePlan and the batching machinery for a single plugin with no
// policy behind it. The stage is always pre_request and ExecInput carries a nil
// Event and a zero Scope, so a plugin opting in must be one that needs none of
// them — see Previewable.
//
// A rejection is a successful preview: the operator asked what the plugin would
// do, and refusing the request is the answer. Only a failure to run at all — an
// unknown plugin, settings the plugin will not accept — comes back as an error.
func (s *previewService) Preview(ctx context.Context, in PreviewInput) (PreviewResult, error) {
	plugin, ok := s.registry.Get(in.Slug)
	if !ok {
		return PreviewResult{}, fmt.Errorf("%w: unknown plugin %q", commonerrors.ErrNotFound, in.Slug)
	}
	if !previewable(plugin) {
		return PreviewResult{}, fmt.Errorf("%w: %s cannot be previewed", ErrPluginNotPreviewable, in.Slug)
	}
	if err := plugin.ValidateConfig(in.Settings); err != nil {
		return PreviewResult{}, errors.Join(commonerrors.ErrInvalidConfig, err)
	}

	// The preview must not answer for a policy the API would refuse to store, so it
	// applies the same mode check the create path uses.
	mode := in.Mode.Normalize()
	if err := ValidateMode(plugin, mode); err != nil {
		return PreviewResult{}, errors.Join(commonerrors.ErrValidation, err)
	}

	ctx, cancel := context.WithTimeout(ctx, previewTimeout)
	defer cancel()

	result, err := plugin.Execute(ctx, ExecInput{
		Stage:  policy.StagePreRequest,
		Mode:   mode,
		Config: policy.PluginConfig{Settings: in.Settings},
		Request: &infracontext.RequestContext{
			Body:    in.Body,
			Headers: in.Headers,
		},
	})
	if pluginErr, isPluginErr := AsPluginError(err); isPluginErr {
		return PreviewResult{
			Decision: PreviewRejected,
			Status:   pluginErr.StatusCode,
			Type:     pluginErr.Type,
			Message:  pluginErr.Message,
		}, nil
	}
	if err != nil {
		return PreviewResult{}, err
	}

	// A plugin can also block by short-circuiting the chain instead of returning a
	// PluginError (executor.go handles both), and reporting that as "unchanged" would
	// tell the operator the opposite of what happens.
	if result != nil && result.StopUpstream {
		return PreviewResult{
			Decision: PreviewRejected,
			Status:   statusOr(result.StatusCode, http.StatusForbidden),
			Message:  string(result.Body),
		}, nil
	}

	// A plugin that mutates nothing returns a Result with no body, so the sample
	// is echoed back rather than reported as an empty rewrite.
	if result == nil || len(result.RequestBody) == 0 {
		return PreviewResult{
			Decision:    PreviewUnchanged,
			RequestBody: in.Body,
			Status:      statusOr(resultStatus(result), http.StatusOK),
		}, nil
	}
	return PreviewResult{
		Decision:    PreviewRewritten,
		RequestBody: result.RequestBody,
		Status:      statusOr(result.StatusCode, http.StatusOK),
	}, nil
}

func resultStatus(result *Result) int {
	if result == nil {
		return 0
	}
	return result.StatusCode
}

// statusOr keeps a zero StatusCode from reaching the console as a literal 0.
func statusOr(status, fallback int) int {
	if status == 0 {
		return fallback
	}
	return status
}
