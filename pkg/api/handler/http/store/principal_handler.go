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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

// PrincipalHandler serves the admin preview of one principal's Store state —
// what the Portal shows that user: their installs and requests, and which
// company sources they have linked their own account to.
type PrincipalHandler struct {
	preview appstore.PrincipalPreview
}

func NewPrincipalHandler(preview appstore.PrincipalPreview) *PrincipalHandler {
	return &PrincipalHandler{preview: preview}
}

type principalInstallResponse struct {
	InstanceID  string    `json:"instance_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	RegistryID  string    `json:"registry_id,omitempty"`
	Registry    string    `json:"registry,omitempty"`
	Status      string    `json:"status"`
	InstalledBy string    `json:"installed_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// principalConnectionResponse never carries token material: only whether the
// principal linked an account for the source and whether it needs a reconnect.
type principalConnectionResponse struct {
	Provider       string     `json:"provider"`
	Code           string     `json:"code,omitempty"`
	RegistryID     string     `json:"registry_id"`
	Registry       string     `json:"registry"`
	Linked         bool       `json:"linked"`
	AccountRef     string     `json:"account_ref,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	NeedsReconnect bool       `json:"needs_reconnect"`
}

type principalResponse struct {
	PrincipalSub string                        `json:"principal_sub"`
	Installs     []principalInstallResponse    `json:"installs"`
	Connections  []principalConnectionResponse `json:"connections"`
}

// Get godoc
// @Summary      Preview a principal's MCP Store state
// @Description  Returns what one user holds on the gateway's Store: installed and pending instances, plus per forwarded-auth source whether they linked their own account. Credential material is never returned.
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        sub         query     string  true  "Principal subject (the user id the gateway sees)"
// @Success      200         {object}  principalResponse
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
	out := principalResponse{
		PrincipalSub: state.PrincipalSub,
		Installs:     make([]principalInstallResponse, 0, len(state.Installs)),
		Connections:  make([]principalConnectionResponse, 0, len(state.Connections)),
	}
	for _, in := range state.Installs {
		row := principalInstallResponse{
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
		row := principalConnectionResponse{
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
