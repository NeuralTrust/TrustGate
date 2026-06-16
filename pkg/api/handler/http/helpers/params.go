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

package helpers

import (
	"errors"
	"strconv"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

const (
	DefaultPage = 1
	DefaultSize = 20
	MaxSize     = 200
)

var ErrInvalidUUIDParam = errors.New("invalid uuid path parameter")
var ErrInvalidPage = errors.New("invalid page parameter")
var ErrInvalidSize = errors.New("invalid size parameter")

func ParseUUIDParam[K ids.Kind](c *fiber.Ctx, name string) (ids.ID[K], error) {
	raw := c.Params(name)
	if raw == "" {
		return ids.ID[K]{}, ErrInvalidUUIDParam
	}
	id, err := ids.Parse[K](raw)
	if err != nil {
		return ids.ID[K]{}, ErrInvalidUUIDParam
	}
	return id, nil
}

// ParseGatewayID parses the required :gateway_id path param shared by every
// gateway-scoped collection handler (create/list).
func ParseGatewayID(c *fiber.Ctx) (ids.GatewayID, error) {
	return ParseUUIDParam[ids.GatewayKind](c, "gateway_id")
}

// ParseGatewayScopedID parses the required :gateway_id and :id path params
// shared by every gateway-scoped sub-resource handler (get/update/delete).
func ParseGatewayScopedID[K ids.Kind](c *fiber.Ctx) (ids.GatewayID, ids.ID[K], error) {
	gatewayID, err := ParseGatewayID(c)
	if err != nil {
		return ids.GatewayID{}, ids.ID[K]{}, err
	}
	id, err := ParseUUIDParam[K](c, "id")
	if err != nil {
		return ids.GatewayID{}, ids.ID[K]{}, err
	}
	return gatewayID, id, nil
}

func ParseConsumerAssociationID[K ids.Kind](c *fiber.Ctx, targetParam string) (ids.GatewayID, ids.ConsumerID, ids.ID[K], error) {
	gatewayID, consumerID, err := ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return ids.GatewayID{}, ids.ConsumerID{}, ids.ID[K]{}, err
	}
	targetID, err := ParseUUIDParam[K](c, targetParam)
	if err != nil {
		return ids.GatewayID{}, ids.ConsumerID{}, ids.ID[K]{}, err
	}
	return gatewayID, consumerID, targetID, nil
}

func ParsePage(c *fiber.Ctx) (int, error) {
	raw := c.Query("page")
	if raw == "" {
		return DefaultPage, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		return 0, ErrInvalidPage
	}
	return v, nil
}

func ParseSize(c *fiber.Ctx) (int, error) {
	raw := c.Query("size")
	if raw == "" {
		return DefaultSize, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		return 0, ErrInvalidSize
	}
	if v > MaxSize {
		return MaxSize, nil
	}
	return v, nil
}
