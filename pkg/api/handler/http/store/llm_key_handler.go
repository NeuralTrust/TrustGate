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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	storerequest "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store/request"
	storeresponse "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

// LLMKeyHandler serves the caller's own personal LLM key, and the create an
// admin runs for another user.
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
// @Description  Issues the caller's personal key on the gateway, the one that belongs to no group, linked to no consumer, and returns its secret once. expires_at is optional: when set it must fall within the next 366 days; absent, null or empty, the key never expires. One personal key per user per gateway; owner_id, principal_sub, consumer_id and any group in the body are ignored (a key for a group is issued by the admin route). The key records the email the caller's token carries, which every call it makes is shown under.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                            true  "Gateway id"  format(uuid)
// @Param        body        body      storerequest.CreateLLMKeyRequest  false  "Expiry of the key"
// @Success      201         {object}  storeresponse.IssuedPersonalKeyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody  "Not a signed-in tenant user: service credential, platform token or no user id"
// @Failure      404         {object}  httpio.ErrorBody  "No such gateway"
// @Failure      409         {object}  httpio.ErrorBody  "The caller already holds a key on this gateway"
// @Failure      422         {object}  httpio.ErrorBody  "An out-of-range expires_at, or a hybrid gateway"
// @Router       /v1/gateways/{gateway_id}/store/principal/llm-key [post]
func (h *LLMKeyHandler) Create(c *fiber.Ctx) error {
	gatewayID, owner, err := selfScope(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req storerequest.CreateLLMKeyRequest
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
		}
	}
	expiresAt, err := req.Expiry()
	if err != nil {
		return httpio.WriteError(c, err)
	}
	key, err := h.keys.Create(c.UserContext(), gatewayID, appauth.PersonalKeyOwner{ID: owner, Email: callerEmail(c)}, authdomain.KeyGroup{}, expiresAt)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, storeresponse.FromIssuedPersonalKey(key))
}

// CreateForUser godoc
// @Summary      Create a user's personal LLM key
// @Description  Issues the personal key of the user named in the path, on the gateway, linked to no consumer, and returns its secret once, for the admin to hand over. It is the key the user would create themselves: one per user per gateway, expires_at optional (absent never expires; set, within the next 366 days), and the user rotates or revokes it afterwards as their own. owner_email is the email every call the key makes is shown under; absent, it is recorded when the console next reconciles the key. Which users an admin may issue keys for is the console's call; TrustGate checks only that the gateway is the caller's tenant's. Needs a signed-in tenant user: a service credential or a platform token answers 403.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                                true  "Gateway id"  format(uuid)
// @Param        user_id     path      string                                true  "Platform user id of the key's owner"
// @Param        body        body      storerequest.CreateUserLLMKeyRequest  false  "Expiry of the key and the owner's email"
// @Success      201         {object}  storeresponse.IssuedPersonalKeyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody  "Not a signed-in tenant user: service credential, platform token or no user id"
// @Failure      404         {object}  httpio.ErrorBody  "No such gateway"
// @Failure      409         {object}  httpio.ErrorBody  "The user already holds a key on this gateway"
// @Failure      422         {object}  httpio.ErrorBody  "An out-of-range expires_at, an owner_email that is not an address, or a hybrid gateway"
// @Router       /v1/gateways/{gateway_id}/store/users/{user_id}/llm-key [post]
func (h *LLMKeyHandler) CreateForUser(c *fiber.Ctx) error {
	gatewayID, _, err := selfScope(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req storerequest.CreateUserLLMKeyRequest
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
		}
	}
	expiresAt, err := req.Expiry()
	if err != nil {
		return httpio.WriteError(c, err)
	}
	owner := appauth.PersonalKeyOwner{ID: strings.TrimSpace(c.Params("user_id")), Email: req.OwnerEmail}
	key, err := h.keys.Create(c.UserContext(), gatewayID, owner, authdomain.KeyGroup{}, expiresAt)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, storeresponse.FromIssuedPersonalKey(key))
}

// Rotate godoc
// @Summary      Rotate your personal LLM key
// @Description  Replaces the secret of the caller's personal key (the one that belongs to no group) and returns the new one once. The key keeps its id and every consumer link. Without expires_at or never_expires the current expiry stays, a key that never expires included; a key whose expiry has passed then answers 422. expires_at sets a new expiry within the next 366 days; never_expires true renews it with none. The two cannot be combined (422).
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
// @Failure      422         {object}  httpio.ErrorBody  "Out-of-range expires_at, expires_at with never_expires, or an expired key rotated with neither"
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
	expiry, err := req.Expiry()
	if err != nil {
		return httpio.WriteError(c, err)
	}
	key, err := h.keys.Rotate(c.UserContext(), gatewayID, owner, expiry)
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

// callerEmail is the signed-in user's email, which their key's calls are shown
// under; empty when the token carries none, or nothing that is an address.
func callerEmail(c *fiber.Ctx) string {
	email, _ := c.Locals(string(infracontext.UserEmailContextKey)).(string)
	normalized, err := authdomain.NormalizeOwnerEmail(email)
	if err != nil {
		return ""
	}
	return normalized
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
