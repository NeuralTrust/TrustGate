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

package store

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	storerequest "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store/request"
	storeresponse "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// LLMKeyHandler serves the caller's own personal LLM key.
type LLMKeyHandler struct {
	keys appauth.PersonalKeys
}

// NewLLMKeyHandler returns the handler over keys.
func NewLLMKeyHandler(keys appauth.PersonalKeys) *LLMKeyHandler {
	return &LLMKeyHandler{keys: keys}
}

// Get godoc
// @Summary      Read your personal LLM key
// @Description  Returns the caller's own personal key on the gateway: its id, recognition prefix and suffix, the consumers it is linked to, its expiry and timestamps. The secret is never returned. Acts on the signed-in tenant user only; a service credential or a platform token answers 403.
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  storeresponse.PersonalKeyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody  "Not a signed-in tenant user: service credential, platform token or no user id"
// @Failure      404         {object}  httpio.ErrorBody  "No key for the caller, or no such gateway"
// @Router       /v1/gateways/{gateway_id}/store/principal/llm-key [get]
func (h *LLMKeyHandler) Get(c *fiber.Ctx) error {
	gatewayID, owner, err := selfScope(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	key, err := h.keys.Get(c.UserContext(), gatewayID, owner)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, storeresponse.FromPersonalKey(key))
}

// Create godoc
// @Summary      Create your personal LLM key
// @Description  Issues the caller's personal key on the gateway, linked to no consumer, and returns its secret once. expires_at is required and must fall within the next 90 days. One key per user per gateway; owner_id, principal_sub and consumer_id in the body are ignored.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                            true  "Gateway id"  format(uuid)
// @Param        body        body      storerequest.CreateLLMKeyRequest  true  "Expiry of the key"
// @Success      201         {object}  storeresponse.IssuedPersonalKeyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody  "Not a signed-in tenant user: service credential, platform token or no user id"
// @Failure      404         {object}  httpio.ErrorBody  "No such gateway"
// @Failure      409         {object}  httpio.ErrorBody  "The caller already holds a key on this gateway"
// @Failure      422         {object}  httpio.ErrorBody  "Missing or out-of-range expires_at, or a hybrid gateway"
// @Router       /v1/gateways/{gateway_id}/store/principal/llm-key [post]
func (h *LLMKeyHandler) Create(c *fiber.Ctx) error {
	gatewayID, owner, err := selfScope(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req storerequest.CreateLLMKeyRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	expiresAt, err := req.Expiry()
	if err != nil {
		return httpio.WriteError(c, err)
	}
	key, err := h.keys.Create(c.UserContext(), gatewayID, owner, expiresAt)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, storeresponse.FromIssuedPersonalKey(key))
}

// Rotate godoc
// @Summary      Rotate your personal LLM key
// @Description  Replaces the secret of the caller's personal key and returns the new one once. The key keeps its id and every consumer link. Without expires_at the current expiry stays, unless it has passed; with it, it must fall within the next 90 days.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                            true   "Gateway id"  format(uuid)
// @Param        body        body      storerequest.RotateLLMKeyRequest  false  "Expiry of the new secret"
// @Success      200         {object}  storeresponse.IssuedPersonalKeyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody  "Not a signed-in tenant user: service credential, platform token or no user id"
// @Failure      404         {object}  httpio.ErrorBody  "No key for the caller, or no such gateway"
// @Failure      422         {object}  httpio.ErrorBody  "Out-of-range expires_at, or an expired key rotated without one"
// @Router       /v1/gateways/{gateway_id}/store/principal/llm-key/rotate [post]
func (h *LLMKeyHandler) Rotate(c *fiber.Ctx) error {
	gatewayID, owner, err := selfScope(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req storerequest.RotateLLMKeyRequest
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
		}
	}
	expiresAt, err := req.Expiry()
	if err != nil {
		return httpio.WriteError(c, err)
	}
	key, err := h.keys.Rotate(c.UserContext(), gatewayID, owner, expiresAt)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, storeresponse.FromIssuedPersonalKey(key))
}

// Revoke godoc
// @Summary      Revoke your personal LLM key
// @Description  Deletes the caller's personal key and every consumer link it holds. The caller may create a new one afterwards.
// @Tags         store
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"  format(uuid)
// @Success      204
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody  "Not a signed-in tenant user: service credential, platform token or no user id"
// @Failure      404         {object}  httpio.ErrorBody  "No key for the caller, or no such gateway"
// @Router       /v1/gateways/{gateway_id}/store/principal/llm-key [delete]
func (h *LLMKeyHandler) Revoke(c *fiber.Ctx) error {
	gatewayID, owner, err := selfScope(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.keys.Revoke(c.UserContext(), gatewayID, owner); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}

func selfScope(c *fiber.Ctx) (ids.GatewayID, string, error) {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return gatewayID, "", err
	}
	identity := middleware.AdminIdentityFromContext(c)
	owner := callerSubject(c)
	if identity.Kind != middleware.AdminIdentityHuman || identity.TenantID == "" || owner == "" {
		return gatewayID, "", fmt.Errorf("a personal key belongs to a signed-in user: %w", commonerrors.ErrForbidden)
	}
	return gatewayID, owner, nil
}
