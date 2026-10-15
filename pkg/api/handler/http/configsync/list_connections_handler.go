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

	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsync/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncconn"
	"github.com/gofiber/fiber/v2"
)

// ConnectionLister reads persisted data-plane connection state, optionally
// filtered by opaque scope.
type ConnectionLister interface {
	List(ctx context.Context, scope string, page *listing.Page) ([]configsyncconn.Connection, error)
}

type ListConnectionsHandler struct {
	lister ConnectionLister
}

func NewListConnectionsHandler(lister ConnectionLister) *ListConnectionsHandler {
	return &ListConnectionsHandler{lister: lister}
}

// Handle godoc
// @Summary      List config-sync data-plane connections
// @Description  Returns the observed data-plane Sync connections of one gateway. Answers "is this data plane online?". A tenant caller must pass the id of one of its gateways as scope; only a platform caller may omit it to list every data plane. Pass page and size to paginate.
// @Tags         config-sync
// @Produce      json
// @Security     BearerAuth
// @Param        scope  query     string  false  "Gateway id whose data planes to list (exact match). Required for tenant callers."
// @Param        page   query     int     false  "Page number (1-based); omit page and size for every match"
// @Param        size   query     int     false  "Page size (max 200)"
// @Success      200    {object}  response.ListConnectionsResponse
// @Failure      400    {object}  httpio.ErrorBody
// @Failure      401    {object}  httpio.ErrorBody
// @Failure      404    {object}  httpio.ErrorBody
// @Failure      422    {object}  httpio.ErrorBody
// @Failure      500    {object}  httpio.ErrorBody
// @Router       /v1/config-sync/connections [get]
func (h *ListConnectionsHandler) Handle(c *fiber.Ctx) error {
	page, err := parsePage(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	conns, err := h.lister.List(c.UserContext(), middleware.ConfigSyncScope(c), page)
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

// parsePage reads page and size only when the caller asks for them, so a
// listing without either keeps returning every match.
func parsePage(c *fiber.Ctx) (*listing.Page, error) {
	if c.Query("page") == "" && c.Query("size") == "" {
		return nil, nil
	}
	page, err := httpio.ParseListingPage(c)
	if err != nil {
		return nil, err
	}
	return &page, nil
}
