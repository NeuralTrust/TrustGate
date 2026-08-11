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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
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

func TestParseSearch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "empty", target: "/test", want: ""},
		{name: "name alias", target: "/test?name=foo", want: "foo"},
		{name: "search preferred", target: "/test?search=bar&name=foo", want: "bar"},
		{name: "search only", target: "/test?search=baz", want: "baz"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := runInCtx(t, tc.target, "/test", func(c *fiber.Ctx) (string, error) {
				return ParseSearch(c), nil
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseSort(t *testing.T) {
	t.Parallel()
	allowed := []string{"name", "created_at"}

	tests := []struct {
		name    string
		target  string
		want    listing.Sort
		wantErr error
	}{
		{name: "empty is zero", target: "/test", want: listing.Sort{}},
		{name: "field defaults to asc", target: "/test?sort=name", want: listing.Sort{Field: "name", Direction: listing.Asc}},
		{name: "explicit desc", target: "/test?sort=created_at&order=desc", want: listing.Sort{Field: "created_at", Direction: listing.Desc}},
		{name: "explicit asc", target: "/test?sort=name&order=asc", want: listing.Sort{Field: "name", Direction: listing.Asc}},
		{name: "unknown field", target: "/test?sort=priority", wantErr: ErrInvalidSort},
		{name: "unknown order", target: "/test?sort=name&order=sideways", wantErr: ErrInvalidSort},
		{name: "order without sort", target: "/test?order=desc", wantErr: ErrInvalidSort},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := runInCtx(t, tc.target, "/test", func(c *fiber.Ctx) (listing.Sort, error) {
				return ParseSort(c, allowed)
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
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseOptionalBool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		wantNil bool
		want    bool
		wantErr error
	}{
		{name: "missing", target: "/test", wantNil: true},
		{name: "true", target: "/test?active=true", want: true},
		{name: "false", target: "/test?active=false", want: false},
		{name: "invalid", target: "/test?active=maybe", wantErr: ErrInvalidFilter},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := runInCtx(t, tc.target, "/test", func(c *fiber.Ctx) (*bool, error) {
				return ParseOptionalBool(c, "active")
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
			if tc.wantNil {
				if got != nil {
					t.Fatalf("got %v, want nil", *got)
				}
				return
			}
			if got == nil || *got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseCSVQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   []string
	}{
		{name: "missing", target: "/test", want: nil},
		{name: "single", target: "/test?category=Guardrails", want: []string{"Guardrails"}},
		{name: "comma separated", target: "/test?category=Guardrails,Quota", want: []string{"Guardrails", "Quota"}},
		{name: "trims spaces", target: "/test?category=Guardrails,%20Quota", want: []string{"Guardrails", "Quota"}},
		{name: "repeated keys", target: "/test?type=a&type=b", want: []string{"a", "b"}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := runInCtx(t, tc.target, "/test", func(c *fiber.Ctx) ([]string, error) {
				name := "category"
				if strings.Contains(tc.target, "type=") {
					name = "type"
				}
				return ParseCSVQuery(c, name), nil
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}
