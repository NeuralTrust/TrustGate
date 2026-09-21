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

package policy

import (
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/response"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domainpolicy "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/gofiber/fiber/v2"
)

type PreviewPolicyHandler struct {
	previewer appplugins.PreviewService
}

func NewPreviewPolicyHandler(previewer appplugins.PreviewService) *PreviewPolicyHandler {
	return &PreviewPolicyHandler{previewer: previewer}
}

// Handle godoc
// @Summary      Preview a policy configuration
// @Description  Runs a previewable plugin against a sample request body without storing anything or sending traffic. Returns 200 for every outcome the plugin can produce, including a rejection; inspect decision. Only plugins that declare themselves previewable are accepted.
// @Tags         policies
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                        true  "Gateway id"  format(uuid)
// @Param        body        body      request.PreviewPolicyRequest  true  "Configuration and sample request"
// @Success      200         {object}  response.PreviewPolicyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies/preview [post]
func (h *PreviewPolicyHandler) Handle(c *fiber.Ctx) error {
	// The id is parsed to reject a malformed path early; the authz middleware on the
	// group has already gated on it. The preview itself is gateway-independent — it
	// reads and writes nothing for that gateway — so the value is deliberately unused.
	if _, err := httpio.ParseGatewayID(c); err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.PreviewPolicyRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}

	result, err := h.previewer.Preview(c.UserContext(), appplugins.PreviewInput{
		Slug:     req.Slug,
		Settings: req.Settings,
		Mode:     domainpolicy.Mode(req.Mode),
		Body:     req.Body,
		Headers:  req.Headers,
	})
	if err != nil {
		return httpio.WriteError(c, previewError(err))
	}

	return httpio.WriteOK(c, response.PreviewPolicyResponse{
		Decision:    string(result.Decision),
		RequestBody: result.RequestBody,
		Status:      result.Status,
		Type:        result.Type,
		Message:     result.Message,
	})
}

// previewError keeps "this plugin does not support preview" out of the 500 bucket:
// it is a property of the plugin the caller named, not a failure of the server.
// errors.Join rather than a formatted wrap, so the sentinel stays reachable.
func previewError(err error) error {
	if errors.Is(err, appplugins.ErrPluginNotPreviewable) {
		return errors.Join(commonerrors.ErrValidation, err)
	}
	return err
}
