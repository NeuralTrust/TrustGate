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

package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type fakeRefresher struct {
	fresh *registrydomain.Registry
	calls int
}

func (f *fakeRefresher) Refresh(context.Context, *registrydomain.Registry) (*registrydomain.Registry, bool) {
	f.calls++
	return f.fresh, f.fresh != nil
}

func TestRefreshRejectedSecret(t *testing.T) {
	t.Parallel()
	src := &registrydomain.Registry{}
	bound := &registrydomain.Registry{}
	bound.BindSecrets(src, "d1")
	fresh := &registrydomain.Registry{}
	r := &fakeRefresher{fresh: fresh}
	f := &forwarder{secrets: r, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		got, ok := f.refreshRejectedSecret(ctx, bound, &ProviderResponse{StatusCode: status})
		if !ok || got != fresh {
			t.Fatalf("status %d: retry %v", status, ok)
		}
	}
	for name, tc := range map[string]struct {
		reg  *registrydomain.Registry
		resp *ProviderResponse
	}{
		"other status":    {bound, &ProviderResponse{StatusCode: http.StatusInternalServerError}},
		"no response":     {bound, nil},
		"literal key":     {&registrydomain.Registry{}, &ProviderResponse{StatusCode: http.StatusUnauthorized}},
		"stream returned": {bound, &ProviderResponse{StatusCode: http.StatusUnauthorized, Stream: func(func([]byte, error) bool) {}}},
	} {
		before := r.calls
		if _, ok := f.refreshRejectedSecret(ctx, tc.reg, tc.resp); ok || r.calls != before {
			t.Fatalf("%s: must neither refresh nor retry", name)
		}
	}
	if _, ok := (&forwarder{}).refreshRejectedSecret(ctx, bound, &ProviderResponse{StatusCode: http.StatusUnauthorized}); ok {
		t.Fatal("no refresher, no retry")
	}
}
