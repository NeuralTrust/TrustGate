// Package helpers contains thin HTTP-layer utilities shared across the
// admin and proxy handlers. Helpers MUST NOT carry business logic; they
// translate between Fiber primitives and small typed values.
package helpers

import (
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Pagination defaults and bounds shared by every list endpoint.
const (
	DefaultPage = 1
	DefaultSize = 20
	MaxSize     = 200
)

// ErrInvalidUUIDParam is returned when a path parameter is not a UUID.
var ErrInvalidUUIDParam = errors.New("invalid uuid path parameter")

// ErrInvalidPage is returned when ?page= is not a positive integer.
var ErrInvalidPage = errors.New("invalid page parameter")

// ErrInvalidSize is returned when ?size= is not a positive integer.
var ErrInvalidSize = errors.New("invalid size parameter")

// ParseUUIDParam extracts and parses a UUID path parameter (e.g. ":id").
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

// ParsePage reads ?page= from the query string. Missing or empty values
// fall back to DefaultPage. Negative or zero values are rejected.
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

// ParseSize reads ?size= from the query string. Missing values fall back
// to DefaultSize. Values above MaxSize are clamped to MaxSize. Negative
// or zero values are rejected.
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
