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
	case errors.Is(err, commonerrors.ErrConflict):
		return fiber.StatusConflict, ErrorBody{Error: "conflict", Message: err.Error()}
	case errors.Is(err, commonerrors.ErrValidation):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "validation_failed", Message: err.Error()}
	case errors.Is(err, commonerrors.ErrInvalidConfig):
		return fiber.StatusUnprocessableEntity, ErrorBody{Error: "invalid_config", Message: err.Error()}
	default:
		return fiber.StatusInternalServerError, ErrorBody{Error: "internal_error"}
	}
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
