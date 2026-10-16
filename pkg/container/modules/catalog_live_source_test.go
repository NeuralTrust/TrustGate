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

package modules

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/require"
)

type stubModelLister struct {
	err error
}

func (s stubModelLister) ListLiveModels(context.Context, *providers.Config) ([]providers.LiveModel, error) {
	return nil, s.err
}

type stubListerLocator struct {
	lister providers.ModelLister
}

func (s stubListerLocator) Get(string) (providers.Client, error) {
	return nil, errors.New("not used")
}

func (s stubListerLocator) GetTester(string) (providers.ConnectionTester, error) {
	return nil, errors.New("not used")
}

func (s stubListerLocator) GetModelLister(string) (providers.ModelLister, error) {
	return s.lister, nil
}

func transportError(cause error) error {
	return fmt.Errorf("%w: request: %w", providers.ErrModelListingFailed, &url.Error{
		Op:  http.MethodGet,
		URL: "https://deleted-resource.services.ai.azure.com/openai/deployments",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: cause},
	})
}

func TestLiveModelSource_List_ClassifiesListingFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		err              error
		wantMisconfigure bool
	}{
		{
			name: "host that does not exist",
			err: transportError(&net.DNSError{
				Err:        "no such host",
				Name:       "deleted-resource.services.ai.azure.com",
				IsNotFound: true,
			}),
			wantMisconfigure: true,
		},
		{
			name: "temporary DNS failure",
			err: transportError(&net.DNSError{
				Err:         "server misbehaving",
				Name:        "resource.services.ai.azure.com",
				IsTemporary: true,
			}),
		},
		{
			name: "DNS timeout",
			err: transportError(&net.DNSError{
				Err:       "i/o timeout",
				Name:      "resource.services.ai.azure.com",
				IsTimeout: true,
			}),
		},
		{
			name:             "credentials rejected",
			err:              fmt.Errorf("%w: %w", providers.ErrModelListingFailed, &providers.ModelListingStatusError{StatusCode: http.StatusUnauthorized}),
			wantMisconfigure: true,
		},
		{
			name: "provider throttling",
			err:  fmt.Errorf("%w: %w", providers.ErrModelListingFailed, &providers.ModelListingStatusError{StatusCode: http.StatusTooManyRequests}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			source := newLiveModelSource(stubListerLocator{lister: stubModelLister{err: tt.err}})
			_, err := source.List(context.Background(), providers.ProviderAzure, &registrydomain.TargetAuth{}, nil)

			require.Error(t, err)
			require.Equal(t, tt.wantMisconfigure, errors.Is(err, appcatalog.ErrLiveListingMisconfigured))
		})
	}
}
