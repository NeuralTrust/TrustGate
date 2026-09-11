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
	"fmt"
	"log/slog"
	"runtime"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

// ErrorBody is the JSON shape emitted on every error response. Handlers
// MUST go through MapDomainError so the wire format stays consistent.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

const (
	msgNotFound = "No resource matched this request. Check the id in the URL and that it exists for this gateway or tenant."
	msgInternal = "An unexpected error occurred. Retry the request; if it keeps failing, contact support and include the X-Request-ID response header."
	msgValidationHint = "Check the request body fields against the Admin API schema and retry."
	msgConflictHint = "Fetch the current resource, resolve the conflict, and retry."
	msgAlreadyExistsHint = "Use a different unique name or slug, or update the existing resource instead of creating a new one."
	msgHasDependentsHint = "Remove or reassign dependent resources first, then retry the delete."
	msgInvalidConfigHint = "Check the configuration fields and types against the Admin API docs and retry."
	msgResultTooLargeHint = "Narrow the query with filters or pagination (smaller page size) and retry."
)

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
		return fiber.StatusBadRequest, ErrorBody{Error: "invalid_uuid", Message: publicMessage(err, "")}
	case errors.Is(err, ErrInvalidQuery):
		return fiber.StatusBadRequest, ErrorBody{Error: "invalid_query", Message: publicMessage(err, "")}
	case errors.Is(err, ErrInvalidPage), errors.Is(err, ErrInvalidSize):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "invalid_pagination", Message: publicMessage(err, "")}
	case errors.Is(err, ErrInvalidSort):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "invalid_sort", Message: publicMessage(err, "")}
	case errors.Is(err, ErrInvalidFilter):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "invalid_filter", Message: publicMessage(err, "")}
	case errors.Is(err, commonerrors.ErrNotFound):
		return fiber.StatusNotFound, ErrorBody{Error: "not_found", Message: notFoundMessage(err)}
	case errors.Is(err, commonerrors.ErrAlreadyExists):
		return fiber.StatusConflict, ErrorBody{Error: "already_exists", Message: publicMessage(err, msgAlreadyExistsHint)}
	case errors.Is(err, commonerrors.ErrHasDependents):
		return fiber.StatusConflict, ErrorBody{Error: "has_dependents", Message: publicMessage(err, msgHasDependentsHint)}
	case errors.Is(err, commonerrors.ErrConflict):
		return fiber.StatusConflict, ErrorBody{Error: "conflict", Message: publicMessage(err, msgConflictHint)}
	case errors.Is(err, commonerrors.ErrValidation):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "validation_failed", Message: publicMessage(err, msgValidationHint)}
	case errors.Is(err, commonerrors.ErrInvalidConfig):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "invalid_config", Message: publicMessage(err, msgInvalidConfigHint)}
	case errors.Is(err, commonerrors.ErrResultTooLarge):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "result_too_large", Message: publicMessage(err, msgResultTooLargeHint)}
	default:
		return fiber.StatusInternalServerError, ErrorBody{Error: "internal_error", Message: msgInternal}
	}
}

// publicMessage builds a client-facing message from err, optionally appending
// a how-to-fix hint. Bare sentinel text is replaced by the hint alone so the
// wire response stays actionable. Secrets and upstream payloads must never be
// placed in err strings that reach this helper.
func publicMessage(err error, hint string) string {
	msg := strings.TrimSpace(err.Error())
	if isBareSentinel(msg) {
		if hint != "" {
			return hint
		}
		return msg
	}
	if hint == "" || strings.Contains(msg, hint) {
		return msg
	}
	return msg + ". " + hint
}

func isBareSentinel(msg string) bool {
	switch msg {
	case commonerrors.ErrNotFound.Error(),
		commonerrors.ErrAlreadyExists.Error(),
		commonerrors.ErrConflict.Error(),
		commonerrors.ErrHasDependents.Error(),
		commonerrors.ErrValidation.Error(),
		commonerrors.ErrInvalidConfig.Error(),
		commonerrors.ErrResultTooLarge.Error():
		return true
	default:
		return false
	}
}

func notFoundMessage(err error) string {
	msg := strings.TrimSpace(err.Error())
	if msg == "" || msg == commonerrors.ErrNotFound.Error() {
		return msgNotFound
	}
	const suffix = ": " + "resource not found"
	if entity, ok := strings.CutSuffix(msg, suffix); ok && entity != "" && !strings.Contains(entity, " ") {
		return fmt.Sprintf("No %s matched this request. Check the id in the URL and that it exists for this gateway or tenant.", entity)
	}
	if strings.Contains(msg, commonerrors.ErrNotFound.Error()) && msg != commonerrors.ErrNotFound.Error() {
		return msg + ". Check the id in the URL and that it exists for this gateway or tenant."
	}
	return msgNotFound
}

// WriteError is a convenience wrapper around MapDomainError + JSON write.
// Every error funnelled through here is logged at Error level with the caller
// site and a stack trace, so a failing endpoint always leaves a trace even when
// the wire response collapses to a generic code (e.g. 500 "internal_error").
func WriteError(c *fiber.Ctx, err error) error {
	status, body := MapDomainError(err)
	if err != nil {
		logError(c, status, err)
	}
	return c.Status(status).JSON(body)
}

// stackSkip drops the runtime.Callers, logError and WriteError frames so the
// reported origin starts at the handler that called WriteError.
const stackSkip = 3

// stackDepth caps how many frames we walk when building the trace.
const stackDepth = 16

func logError(c *fiber.Ctx, status int, err error) {
	caller, stack := captureStack()
	slog.Default().LogAttrs(c.UserContext(), slog.LevelError, "request failed",
		slog.String("error", err.Error()),
		slog.Int("status", status),
		slog.String("method", c.Method()),
		slog.String("path", c.Path()),
		slog.String("request_id", c.Get(fiber.HeaderXRequestID)),
		slog.String("caller", caller),
		slog.String("stack", stack),
	)
}

// captureStack returns the immediate caller ("file:line") and a multi-frame
// trace of the application call path that reached WriteError. Frames inside the
// fiber framework and the Go runtime are trimmed to keep the trace readable.
func captureStack() (caller string, stack string) {
	pcs := make([]uintptr, stackDepth)
	n := runtime.Callers(stackSkip, pcs)
	if n == 0 {
		return "", ""
	}
	frames := runtime.CallersFrames(pcs[:n])
	var sb strings.Builder
	for {
		frame, more := frames.Next()
		if frame.Function == "" {
			break
		}
		if strings.Contains(frame.Function, "gofiber/fiber") {
			break
		}
		if caller == "" {
			caller = fmt.Sprintf("%s:%d", frame.File, frame.Line)
		}
		fmt.Fprintf(&sb, "%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}
	return caller, strings.TrimRight(sb.String(), "\n")
}
