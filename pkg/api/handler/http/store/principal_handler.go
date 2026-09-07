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
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"strings"
)

type PrincipalHandler struct {
	preview   appstore.PrincipalPreview
	installer appstore.PrincipalInstaller
}

func NewPrincipalHandler(preview appstore.PrincipalPreview, installer appstore.PrincipalInstaller) *PrincipalHandler {
	return &PrincipalHandler{preview: preview, installer: installer}
}

func validateInstall(r storerequest.Install) error {
	if strings.TrimSpace(r.PrincipalSub) == "" {
		return fmt.Errorf("principal_sub is required: %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Code) == "" {
		return fmt.Errorf("code is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

// Get godoc
// @Summary      Preview a principal's MCP Store state
// @Description  Returns what one user holds on the gateway's Store: installed and pending instances, plus per forwarded-auth source whether they linked their own account. Credential material is never returned.
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        sub         query     string  true  "Principal subject (the user id the gateway sees)"
// @Success      200         {object}  storeresponse.Principal
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/principal [get]
func (h *PrincipalHandler) Get(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	sub := strings.TrimSpace(c.Query("sub"))
	if sub == "" {
		return httpio.WriteError(c, fmt.Errorf("sub is required: %w", commonerrors.ErrValidation))
	}
	state, err := h.preview.Preview(c.UserContext(), gatewayID, sub)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := storeresponse.Principal{
		PrincipalSub: state.PrincipalSub,
		Installs:     make([]storeresponse.PrincipalInstall, 0, len(state.Installs)),
		Connections:  make([]storeresponse.PrincipalConnection, 0, len(state.Connections)),
	}
	for _, in := range state.Installs {
		row := storeresponse.PrincipalInstall{
			InstanceID:  in.InstanceID.String(),
			Code:        in.Code,
			Name:        in.Name,
			Registry:    in.Registry,
			Status:      string(in.Status),
			InstalledBy: in.InstalledBy,
			CreatedAt:   in.CreatedAt,
			UpdatedAt:   in.UpdatedAt,
		}
		if !in.RegistryID.IsNil() {
			row.RegistryID = in.RegistryID.String()
		}
		out.Installs = append(out.Installs, row)
	}
	for _, conn := range state.Connections {
		row := storeresponse.PrincipalConnection{
			Provider:       conn.Provider,
			Code:           conn.Code,
			RegistryID:     conn.RegistryID.String(),
			Registry:       conn.Registry,
			Linked:         conn.Linked,
			AccountRef:     conn.AccountRef,
			NeedsReconnect: conn.NeedsReconnect,
		}
		if !conn.ExpiresAt.IsZero() {
			exp := conn.ExpiresAt
			row.ExpiresAt = &exp
		}
		out.Connections = append(out.Connections, row)
	}
	return httpio.WriteOK(c, out)
}

// Install godoc
// @Summary      Install or request a Store server for a principal
// @Description  Runs the Store installer as the given user (their live access level applies): installs at once when allowed, records an approval request otherwise. Same outcome the user's own client would get.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string          true  "Gateway id"  format(uuid)
// @Param        body        body      storerequest.Install  true  "Who and what"
// @Success      200         {object}  storeresponse.Install
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody  "The principal's access level is None"
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/principal/installs [post]
func (h *PrincipalHandler) Install(c *fiber.Ctx) error {
	if h.installer == nil {
		return httpio.WriteError(c, fmt.Errorf("store installer: %w", commonerrors.ErrNotFound))
	}
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req storerequest.Install
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := validateInstall(req); err != nil {
		return httpio.WriteError(c, err)
	}
	var registryID ids.RegistryID
	if raw := strings.TrimSpace(req.InstanceID); raw != "" {
		parsed, err := ids.Parse[ids.RegistryKind](raw)
		if err != nil {
			return httpio.WriteError(c, fmt.Errorf("invalid instance_id: %w", commonerrors.ErrValidation))
		}
		registryID = parsed
	}
	res, err := h.installer.InstallFor(c.UserContext(), appstore.OnBehalfInstallRequest{
		GatewayID:    gatewayID,
		PrincipalSub: req.PrincipalSub,
		Code:         req.Code,
		Groups:       req.Groups,
		RegistryID:   registryID,
		Actor:        callerActor(c),
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := storeresponse.Install{
		Code:                   res.Code,
		Name:                   res.Name,
		Status:                 string(res.Status),
		InstanceID:             res.InstanceID,
		Pending:                res.Pending,
		AlreadyInstalled:       res.AlreadyInstalled,
		RequiresAuth:           res.RequiresAuth,
		RequiresConfig:         res.RequiresConfig,
		RequiresAdminSetup:     res.RequiresAdminSetup,
		RequiresInstanceChoice: res.RequiresInstanceChoice,
	}
	for _, choice := range res.InstanceChoices {
		out.InstanceChoices = append(out.InstanceChoices, storeresponse.InstanceChoice{RegistryID: choice.RegistryID.String(), Name: choice.Name})
	}
	return httpio.WriteOK(c, out)
}
