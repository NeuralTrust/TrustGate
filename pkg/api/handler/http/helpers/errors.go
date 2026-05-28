package helpers

import (
	"errors"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

// ErrorBody is the JSON shape emitted on every error response. Handlers
// MUST go through MapDomainError so the wire format stays consistent.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// MapDomainError translates an application/domain error into the matching
// HTTP status code and a stable error code string. Entity-specific
// sentinels add their cases here as their `<entity>-a` slices land.
//
// Unknown errors collapse to 500 + "internal_error" — callers should
// have already logged the underlying error with the request context.
func MapDomainError(err error) (int, ErrorBody) {
	switch {
	case err == nil:
		return fiber.StatusOK, ErrorBody{}
	case errors.Is(err, ErrInvalidUUIDParam):
		return fiber.StatusBadRequest, ErrorBody{Error: "invalid_uuid", Message: err.Error()}
	case errors.Is(err, ErrInvalidPage), errors.Is(err, ErrInvalidSize):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "invalid_pagination", Message: err.Error()}
	case errors.Is(err, commonerrors.ErrNotFound):
		return fiber.StatusNotFound, ErrorBody{Error: "not_found"}
	case errors.Is(err, commonerrors.ErrAlreadyExists):
		return fiber.StatusConflict, ErrorBody{Error: "already_exists", Message: err.Error()}
	case errors.Is(err, commonerrors.ErrHasDependents):
		return fiber.StatusConflict, ErrorBody{Error: "has_dependents", Message: err.Error()}
	case errors.Is(err, commonerrors.ErrValidation):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "validation_failed", Message: err.Error()}
	case errors.Is(err, commonerrors.ErrInvalidConfig):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "invalid_config", Message: err.Error()}
	default:
		return fiber.StatusInternalServerError, ErrorBody{Error: "internal_error"}
	}
}

// WriteError is a convenience wrapper around MapDomainError + JSON write.
func WriteError(c *fiber.Ctx, err error) error {
	status, body := MapDomainError(err)
	return c.Status(status).JSON(body)
}
