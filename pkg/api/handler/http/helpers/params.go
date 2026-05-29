package helpers

import (
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const (
	DefaultPage = 1
	DefaultSize = 20
	MaxSize     = 200
)

var ErrInvalidUUIDParam = errors.New("invalid uuid path parameter")
var ErrInvalidPage = errors.New("invalid page parameter")
var ErrInvalidSize = errors.New("invalid size parameter")

func ParseUUIDParam(c *fiber.Ctx, name string) (uuid.UUID, error) {
	raw := c.Params(name)
	if raw == "" {
		return uuid.Nil, ErrInvalidUUIDParam
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, ErrInvalidUUIDParam
	}
	return id, nil
}

// ParseGatewayID parses the required :gateway_id path param shared by every
// gateway-scoped collection handler (create/list).
func ParseGatewayID(c *fiber.Ctx) (uuid.UUID, error) {
	return ParseUUIDParam(c, "gateway_id")
}

// ParseGatewayScopedID parses the required :gateway_id and :id path params
// shared by every gateway-scoped sub-resource handler (get/update/delete).
func ParseGatewayScopedID(c *fiber.Ctx) (gatewayID, id uuid.UUID, err error) {
	gatewayID, err = ParseGatewayID(c)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	id, err = ParseUUIDParam(c, "id")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return gatewayID, id, nil
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
