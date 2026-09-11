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
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

func TestMapDomainError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         error
		wantStatus  int
		wantCode    string
		wantMsgPart string // substring that must appear in Message (empty = no check)
		wantMsgEmpty bool
	}{
		{name: "nil error → 200 empty", err: nil, wantStatus: fiber.StatusOK, wantCode: "", wantMsgEmpty: true},
		{name: "invalid uuid → 400", err: ErrInvalidUUIDParam, wantStatus: fiber.StatusBadRequest, wantCode: "invalid_uuid", wantMsgPart: "UUID"},
		{name: "invalid query → 400", err: ErrInvalidQuery, wantStatus: fiber.StatusBadRequest, wantCode: "invalid_query", wantMsgPart: "query"},
		{name: "invalid page → 422", err: ErrInvalidPage, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_pagination", wantMsgPart: "page"},
		{name: "invalid size → 422", err: ErrInvalidSize, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_pagination", wantMsgPart: "size"},
		{name: "invalid sort → 422", err: ErrInvalidSort, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_sort", wantMsgPart: "sort"},
		{name: "invalid filter → 422", err: ErrInvalidFilter, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_filter", wantMsgPart: "filter"},
		{name: "not found → 404 with guidance", err: commonerrors.ErrNotFound, wantStatus: fiber.StatusNotFound, wantCode: "not_found", wantMsgPart: "Check the id"},
		{name: "wrapped not found → 404", err: fmt.Errorf("repo: %w", commonerrors.ErrNotFound), wantStatus: fiber.StatusNotFound, wantCode: "not_found", wantMsgPart: "Check the id"},
		{name: "entity not found → 404 names entity", err: fmt.Errorf("gateway: %w", commonerrors.ErrNotFound), wantStatus: fiber.StatusNotFound, wantCode: "not_found", wantMsgPart: "gateway"},
		{name: "already exists → 409", err: commonerrors.ErrAlreadyExists, wantStatus: fiber.StatusConflict, wantCode: "already_exists", wantMsgPart: "unique"},
		{name: "has dependents → 409", err: commonerrors.ErrHasDependents, wantStatus: fiber.StatusConflict, wantCode: "has_dependents", wantMsgPart: "dependent"},
		{name: "conflict → 409", err: commonerrors.ErrConflict, wantStatus: fiber.StatusConflict, wantCode: "conflict", wantMsgPart: "conflict"},
		{name: "validation → 422", err: commonerrors.ErrValidation, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "validation_failed", wantMsgPart: "schema"},
		{name: "validation with detail → 422 keeps detail", err: fmt.Errorf("tenant_id is required: %w", commonerrors.ErrValidation), wantStatus: fiber.StatusUnprocessableEntity, wantCode: "validation_failed", wantMsgPart: "tenant_id is required"},
		{name: "invalid config → 422", err: commonerrors.ErrInvalidConfig, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_config", wantMsgPart: "configuration"},
		{name: "result too large → 422", err: commonerrors.ErrResultTooLarge, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "result_too_large", wantMsgPart: "pagination"},
		{name: "unknown → 500 without leaking", err: errors.New("boom secret=hunter2"), wantStatus: fiber.StatusInternalServerError, wantCode: "internal_error", wantMsgPart: "X-Request-ID"},
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
			if tc.wantMsgEmpty {
				if body.Message != "" {
					t.Fatalf("message = %q, want empty", body.Message)
				}
				return
			}
			if tc.wantMsgPart != "" && !strings.Contains(body.Message, tc.wantMsgPart) {
				t.Fatalf("message = %q, want substring %q", body.Message, tc.wantMsgPart)
			}
			// 500 must never echo the underlying error string.
			if status == fiber.StatusInternalServerError && strings.Contains(body.Message, "hunter2") {
				t.Fatalf("internal_error message leaked underlying error: %q", body.Message)
			}
		})
	}
}
