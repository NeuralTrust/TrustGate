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
		name          string
		err           error
		wantStatus    int
		wantCode      string
		wantMsgSubstr string
		wantMsgExact  string
		wantEmptyMsg  bool
	}{
		{name: "nil error → 200 empty", err: nil, wantStatus: fiber.StatusOK, wantCode: "", wantEmptyMsg: true},
		{name: "invalid uuid → 400", err: ErrInvalidUUIDParam, wantStatus: fiber.StatusBadRequest, wantCode: "invalid_uuid", wantMsgSubstr: "UUID"},
		{name: "invalid uuid with param name → 400", err: fmt.Errorf("path parameter %q is not a valid UUID: %w", "gateway_id", ErrInvalidUUIDParam), wantStatus: fiber.StatusBadRequest, wantCode: "invalid_uuid", wantMsgSubstr: "gateway_id"},
		{name: "invalid query → 400", err: ErrInvalidQuery, wantStatus: fiber.StatusBadRequest, wantCode: "invalid_query", wantMsgSubstr: "query"},
		{name: "invalid page → 422", err: ErrInvalidPage, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_pagination", wantMsgSubstr: "page"},
		{name: "invalid size → 422", err: ErrInvalidSize, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_pagination", wantMsgSubstr: "size"},
		{name: "invalid sort → 422", err: ErrInvalidSort, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_sort", wantMsgSubstr: "sort"},
		{name: "invalid filter → 422", err: ErrInvalidFilter, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_filter", wantMsgSubstr: "true or false"},
		{name: "not found → 404 with message", err: commonerrors.ErrNotFound, wantStatus: fiber.StatusNotFound, wantCode: "not_found", wantMsgSubstr: "not found"},
		{name: "wrapped not found → 404 keeps entity context", err: fmt.Errorf("gateway not found; verify the gateway id exists: %w", commonerrors.ErrNotFound), wantStatus: fiber.StatusNotFound, wantCode: "not_found", wantMsgSubstr: "gateway"},
		{name: "already exists → 409", err: commonerrors.ErrAlreadyExists, wantStatus: fiber.StatusConflict, wantCode: "already_exists", wantMsgSubstr: "already exists"},
		{name: "has dependents → 409", err: commonerrors.ErrHasDependents, wantStatus: fiber.StatusConflict, wantCode: "has_dependents", wantMsgSubstr: "dependents"},
		{name: "conflict → 409", err: commonerrors.ErrConflict, wantStatus: fiber.StatusConflict, wantCode: "conflict", wantMsgSubstr: "conflict"},
		{name: "validation → 422", err: commonerrors.ErrValidation, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "validation_failed", wantMsgSubstr: "validation"},
		{name: "invalid config → 422", err: commonerrors.ErrInvalidConfig, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "invalid_config", wantMsgSubstr: "configuration"},
		{name: "result too large → 422", err: commonerrors.ErrResultTooLarge, wantStatus: fiber.StatusUnprocessableEntity, wantCode: "result_too_large", wantMsgSubstr: "too large"},
		{name: "unknown → 500 safe message", err: errors.New("boom secret=sk-live-xxxx upstream=provider payload"), wantStatus: fiber.StatusInternalServerError, wantCode: "internal_error", wantMsgExact: msgInternalError},
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
			if tc.wantEmptyMsg {
				if body.Message != "" {
					t.Fatalf("message = %q, want empty", body.Message)
				}
				return
			}
			if tc.wantMsgExact != "" {
				if body.Message != tc.wantMsgExact {
					t.Fatalf("message = %q, want %q", body.Message, tc.wantMsgExact)
				}
				return
			}
			if tc.wantMsgSubstr != "" && !strings.Contains(body.Message, tc.wantMsgSubstr) {
				t.Fatalf("message = %q, want substring %q", body.Message, tc.wantMsgSubstr)
			}
			if body.Message == "" {
				t.Fatal("message is empty; Admin API errors should be actionable")
			}
		})
	}
}

func TestMapDomainError_InternalErrorDoesNotLeak(t *testing.T) {
	t.Parallel()
	secret := "sk-live-super-secret-token"
	_, body := MapDomainError(fmt.Errorf("upstream provider failed: %s", secret))
	if body.Error != "internal_error" {
		t.Fatalf("code = %q, want internal_error", body.Error)
	}
	if strings.Contains(body.Message, secret) {
		t.Fatalf("internal_error message leaked secret material: %q", body.Message)
	}
	if body.Message != msgInternalError {
		t.Fatalf("message = %q, want safe guidance", body.Message)
	}
}