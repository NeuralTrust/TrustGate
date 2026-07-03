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
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

func TestMapDomainError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "nil error → 200 empty", err: nil, wantStatus: fiber.StatusOK, wantCode: ""},
		{name: "invalid uuid → 400", err: ErrInvalidUUIDParam, wantStatus: fiber.StatusBadRequest, wantCode: "invalid_uuid"},
		{name: "invalid page → 422", err: ErrInvalidPage, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_pagination"},
		{name: "invalid size → 422", err: ErrInvalidSize, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_pagination"},
		{name: "not found → 404", err: commonerrors.ErrNotFound, wantStatus: fiber.StatusNotFound, wantCode: "not_found"},
		{name: "wrapped not found → 404", err: fmt.Errorf("repo: %w", commonerrors.ErrNotFound), wantStatus: fiber.StatusNotFound, wantCode: "not_found"},
		{name: "already exists → 409", err: commonerrors.ErrAlreadyExists, wantStatus: fiber.StatusConflict, wantCode: "already_exists"},
		{name: "has dependents → 409", err: commonerrors.ErrHasDependents, wantStatus: fiber.StatusConflict, wantCode: "has_dependents"},
		{name: "conflict → 409", err: commonerrors.ErrConflict, wantStatus: fiber.StatusConflict, wantCode: "conflict"},
		{name: "validation → 422", err: commonerrors.ErrValidation, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "validation_failed"},
		{name: "invalid config → 422", err: commonerrors.ErrInvalidConfig, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_config"},
		{name: "unknown → 500", err: errors.New("boom"), wantStatus: fiber.StatusInternalServerError, wantCode: "internal_error"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, body := MapDomainError(tc.err)
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", status, tc.wantStatus)
			}
			if body.Error != tc.wantCode {
				t.Fatalf("code = %q, want %q", body.Error, tc.wantCode)
			}
		})
	}
}
