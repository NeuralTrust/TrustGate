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

package configsync

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsync/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncconn"
	"github.com/gofiber/fiber/v2"
)

// ConnectionLister reads persisted data-plane connection state, optionally
// filtered by opaque scope.
type ConnectionLister interface {
	List(ctx context.Context, scope string) ([]configsyncconn.Connection, error)
}

type ListConnectionsHandler struct {
	lister ConnectionLister
}

func NewListConnectionsHandler(lister ConnectionLister) *ListConnectionsHandler {
	return &ListConnectionsHandler{lister: lister}
}

// Handle godoc
// @Summary      List config-sync data-plane connections
// @Description  Returns the observed data-plane Sync connections, optionally filtered by opaque scope. Answers "is this data plane online?".
// @Tags         config-sync
// @Produce      json
// @Security     BearerAuth
// @Param        scope  query     string  false  "Filter by opaque scope (exact match); omit for all"
// @Success      200    {object}  response.ListConnectionsResponse
// @Failure      401    {object}  httpio.ErrorBody
// @Failure      500    {object}  httpio.ErrorBody
// @Router       /v1/config-sync/connections [get]
func (h *ListConnectionsHandler) Handle(c *fiber.Ctx) error {
	conns, err := h.lister.List(c.UserContext(), c.Query("scope"))
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := response.ListConnectionsResponse{
		Items: make([]response.ConnectionResponse, 0, len(conns)),
	}
	for _, conn := range conns {
		out.Items = append(out.Items, response.FromConnection(conn))
	}
	return httpio.WriteOK(c, out)
}
