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

package httpio

import (
	"errors"
	"strconv"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
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
var ErrInvalidSort = errors.New("invalid sort parameter")
var ErrInvalidFilter = errors.New("invalid filter parameter")

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

// ParseListingPage parses page and size into a listing.Page.
func ParseListingPage(c *fiber.Ctx) (listing.Page, error) {
	page, err := ParsePage(c)
	if err != nil {
		return listing.Page{}, err
	}
	size, err := ParseSize(c)
	if err != nil {
		return listing.Page{}, err
	}
	return listing.Page{Number: page, Size: size}, nil
}

// ParseSearch returns the search query. `search` takes precedence; `name` is
// kept as a backwards-compatible alias.
func ParseSearch(c *fiber.Ctx) string {
	if s := c.Query("search"); s != "" {
		return s
	}
	return c.Query("name")
}

// ParseSort validates sort/order against an allowed field whitelist. An empty
// sort returns a zero listing.Sort (repository default). Order without sort,
// unknown fields, and unknown directions are rejected.
func ParseSort(c *fiber.Ctx, allowed []string) (listing.Sort, error) {
	field := strings.TrimSpace(c.Query("sort"))
	order := strings.ToLower(strings.TrimSpace(c.Query("order")))
	if field == "" {
		if order != "" {
			return listing.Sort{}, ErrInvalidSort
		}
		return listing.Sort{}, nil
	}
	if !containsString(allowed, field) {
		return listing.Sort{}, ErrInvalidSort
	}
	dir := listing.Asc
	switch order {
	case "", "asc":
		// dir already Asc
	case "desc":
		dir = listing.Desc
	default:
		return listing.Sort{}, ErrInvalidSort
	}
	return listing.Sort{Field: field, Direction: dir}, nil
}

// ParseOptionalBool parses an optional boolean query param. Missing returns nil.
func ParseOptionalBool(c *fiber.Ctx, name string) (*bool, error) {
	raw := c.Query(name)
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, ErrInvalidFilter
	}
	return &v, nil
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
