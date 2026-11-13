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

// Package secretstore serves the admin API of secret stores.
package secretstore

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/secretstore/response"
	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// GatewayFinder reads the gateway a request names.
type GatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gateway.Gateway, error)
}

// ListHandler lists a gateway's secret stores.
type ListHandler struct {
	gateways GatewayFinder
	sources  appsecretstore.SourceResolver
	usages   appsecretstore.UsagesFinder
}

// NewListHandler returns a ListHandler.
func NewListHandler(gateways GatewayFinder, sources appsecretstore.SourceResolver, usages appsecretstore.UsagesFinder) *ListHandler {
	return &ListHandler{gateways: gateways, sources: sources, usages: usages}
}

// Handle godoc
// @Summary      List secret stores
// @Description  Returns the secret stores a gateway may reference, where they are configured and how healthy each is. Never returns addresses, credentials or values.
// @Tags         secret-stores
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  response.ListSecretStoresResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/secret-stores [get]
func (h *ListHandler) Handle(c *fiber.Ctx) error {
	src, uses, err := h.load(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromSource(src, uses))
}

// Usages godoc
// @Summary      List the usages of a secret store
// @Description  Returns every field of the gateway that references the store, with the reference as stored and what the gateway's planes last reported about it: ok, failing (with the error class) or not_reported.
// @Tags         secret-stores
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        name        path      string  true  "Store name"
// @Success      200         {array}   response.SecretStoreUsageResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/secret-stores/{name}/usages [get]
func (h *ListHandler) Usages(c *fiber.Ctx) error {
	_, uses, err := h.load(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromUsages(uses[strings.ToLower(c.Params("name"))]))
}

func (h *ListHandler) load(c *fiber.Ctx) (appsecretstore.Source, map[string][]appsecretstore.Usage, error) {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return appsecretstore.Source{}, nil, err
	}
	ctx := c.UserContext()
	gw, err := h.gateways.FindByID(ctx, gatewayID)
	if err != nil {
		return appsecretstore.Source{}, nil, err
	}
	src, err := h.sources.Source(ctx, gw)
	if err != nil {
		return appsecretstore.Source{}, nil, err
	}
	// A gateway that cannot hold references has no usages to show; reading
	// every entity of it would only cost the console's every form open.
	if !src.Supported {
		return src, nil, nil
	}
	uses, err := h.usages.Usages(ctx, gatewayID)
	if err != nil {
		return appsecretstore.Source{}, nil, err
	}
	src.Annotate(gatewayID, uses)
	return src, uses, nil
}
