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

package registry

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type ValidateOpenAPIRequest struct {
	SpecURL string `json:"spec_url"`
	BaseURL string `json:"base_url,omitempty"`
}

type ValidateOpenAPIToolResponse struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Method      string `json:"method"`
	Path        string `json:"path"`
}

type ValidateOpenAPIResponse struct {
	OK             bool                          `json:"ok"`
	Stage          string                        `json:"stage"`
	OpenAPIVersion string                        `json:"openapi_version,omitempty"`
	Title          string                        `json:"title,omitempty"`
	BaseURL        string                        `json:"base_url,omitempty"`
	ToolCount      int                           `json:"tool_count"`
	Tools          []ValidateOpenAPIToolResponse `json:"tools"`
	Warnings       []appopenapi.Warning          `json:"warnings"`
	Message        string                        `json:"message,omitempty"`
}

type ValidateOpenAPIHandler struct {
	validator appregistry.OpenAPIValidator
}

func NewValidateOpenAPIHandler(validator appregistry.OpenAPIValidator) *ValidateOpenAPIHandler {
	return &ValidateOpenAPIHandler{validator: validator}
}

// Handle godoc
// @Summary      Validate an OpenAPI document
// @Description  Fetches and compiles an OpenAPI 3 document into an MCP tool preview without creating a registry. Always returns 200 for validation outcomes; inspect ok and stage.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                    true  "Gateway id"  format(uuid)
// @Param        body        body      ValidateOpenAPIRequest    true  "OpenAPI source"
// @Success      200         {object}  ValidateOpenAPIResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/validate-openapi [post]
func (h *ValidateOpenAPIHandler) Handle(c *fiber.Ctx) error {
	if _, err := httpio.ParseGatewayID(c); err != nil {
		return httpio.WriteError(c, err)
	}
	var req ValidateOpenAPIRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	req.SpecURL = strings.TrimSpace(req.SpecURL)
	req.BaseURL = strings.TrimSpace(req.BaseURL)
	if !isHTTPURL(req.SpecURL) {
		return httpio.WriteError(c, fmt.Errorf("spec_url must be a valid http(s) URL: %w", commonerrors.ErrValidation))
	}
	if req.BaseURL != "" && !isHTTPURL(req.BaseURL) {
		return httpio.WriteError(c, fmt.Errorf("base_url must be a valid http(s) URL: %w", commonerrors.ErrValidation))
	}
	result := h.validator.Validate(c.UserContext(), appopenapi.Source{
		SpecURL: req.SpecURL,
		BaseURL: req.BaseURL,
	})
	tools := make([]ValidateOpenAPIToolResponse, 0, len(result.Tools))
	for _, tool := range result.Tools {
		tools = append(tools, ValidateOpenAPIToolResponse{
			Name:        tool.Name,
			Description: tool.Description,
			Method:      tool.Method,
			Path:        tool.Path,
		})
	}
	slog.Info("openapi validation",
		slog.Bool("ok", result.OK),
		slog.String("stage", string(result.Stage)),
		slog.String("spec_url", req.SpecURL),
		slog.Int("tool_count", len(tools)),
		slog.String("message", result.Message),
	)
	return httpio.WriteOK(c, ValidateOpenAPIResponse{
		OK:             result.OK,
		Stage:          string(result.Stage),
		OpenAPIVersion: result.OpenAPIVersion,
		Title:          result.Title,
		BaseURL:        result.BaseURL,
		ToolCount:      len(tools),
		Tools:          tools,
		Warnings:       nonNilWarnings(result.Warnings),
		Message:        result.Message,
	})
}

func isHTTPURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func nonNilWarnings(warnings []appopenapi.Warning) []appopenapi.Warning {
	if warnings == nil {
		return []appopenapi.Warning{}
	}
	return warnings
}
