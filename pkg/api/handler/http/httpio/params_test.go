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
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

func runInCtx[T any](t *testing.T, target, route string, fn func(c *fiber.Ctx) (T, error)) (T, error) {
	t.Helper()
	var (
		got    T
		gotErr error
	)
	app := fiber.New()
	app.Get(route, func(c *fiber.Ctx) error {
		got, gotErr = fn(c)
		return c.SendStatus(fiber.StatusOK)
	})
	if _, err := app.Test(httptest.NewRequest(fiber.MethodGet, target, nil)); err != nil {
		t.Fatalf("fiber test request failed: %v", err)
	}
	return got, gotErr
}

func TestParseUUIDParam(t *testing.T) {
	t.Parallel()

	validID := ids.New[ids.GatewayKind]()

	tests := []struct {
		name    string
		target  string
		want    ids.GatewayID
		wantErr error
	}{
		{name: "valid uuid is parsed", target: "/test/" + validID.String(), want: validID},
		{name: "invalid uuid is rejected", target: "/test/not-a-uuid", wantErr: ErrInvalidUUIDParam},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := runInCtx(t, tc.target, "/test/:id", func(c *fiber.Ctx) (ids.GatewayID, error) {
				return ParseUUIDParam[ids.GatewayKind](c, "id")
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got err %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestParseUUIDParam_Missing(t *testing.T) {
	t.Parallel()
	_, err := runInCtx(t, "/test", "/test", func(c *fiber.Ctx) (ids.GatewayID, error) {
		return ParseUUIDParam[ids.GatewayKind](c, "id")
	})
	if !errors.Is(err, ErrInvalidUUIDParam) {
		t.Fatalf("got err %v, want ErrInvalidUUIDParam", err)
	}
}

func TestParsePage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		want    int
		wantErr error
	}{
		{name: "default when missing", target: "/test", want: DefaultPage},
		{name: "valid value", target: "/test?page=5", want: 5},
		{name: "zero rejected", target: "/test?page=0", wantErr: ErrInvalidPage},
		{name: "negative rejected", target: "/test?page=-2", wantErr: ErrInvalidPage},
		{name: "non-integer rejected", target: "/test?page=abc", wantErr: ErrInvalidPage},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := runInCtx(t, tc.target, "/test", func(c *fiber.Ctx) (int, error) {
				return ParsePage(c)
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got err %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		want    int
		wantErr error
	}{
		{name: "default when missing", target: "/test", want: DefaultSize},
		{name: "valid value", target: "/test?size=50", want: 50},
		{name: "clamped at max", target: "/test?size=10000", want: MaxSize},
		{name: "exactly at max", target: "/test?size=200", want: MaxSize},
		{name: "zero rejected", target: "/test?size=0", wantErr: ErrInvalidSize},
		{name: "negative rejected", target: "/test?size=-5", wantErr: ErrInvalidSize},
		{name: "non-integer rejected", target: "/test?size=xyz", wantErr: ErrInvalidSize},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := runInCtx(t, tc.target, "/test", func(c *fiber.Ctx) (int, error) {
				return ParseSize(c)
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got err %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}
