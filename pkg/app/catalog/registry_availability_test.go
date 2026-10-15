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

package catalog_test

import (
	"context"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingFilter stands in for one availability check: it reports what it was
// handed and returns a fixed answer, so the composition is what the test sees.
type recordingFilter struct {
	name   string
	order  *[]string
	got    appcatalog.ServerlessFilterInput
	answer []catalogdomain.Model
}

func (f *recordingFilter) Filter(
	_ context.Context,
	in appcatalog.ServerlessFilterInput,
) []catalogdomain.Model {
	*f.order = append(*f.order, f.name)
	f.got = in
	return f.answer
}

// recordingLiveFilter is a recordingFilter in the live listing's place, which
// may also fail.
type recordingLiveFilter struct {
	*recordingFilter
	err error
}

func (f recordingLiveFilter) Filter(
	ctx context.Context,
	in appcatalog.ServerlessFilterInput,
) ([]catalogdomain.Model, error) {
	return f.recordingFilter.Filter(ctx, in), f.err
}

func scopedInput(models []catalogdomain.Model) appcatalog.ServerlessFilterInput {
	return appcatalog.ServerlessFilterInput{
		ProviderCode: "openai",
		GatewayID:    ids.New[ids.GatewayKind](),
		RegistryID:   ids.New[ids.RegistryKind](),
		Models:       models,
	}
}

func TestRegistryAvailability_FeedsEachFilterThePreviousResult(t *testing.T) {
	var order []string
	serverless := &recordingFilter{name: "serverless", order: &order, answer: catalogModels("gpt-4o", "o3")}
	live := &recordingFilter{name: "live", order: &order, answer: catalogModels("gpt-4o")}

	kept, err := appcatalog.NewRegistryAvailability(serverless, recordingLiveFilter{recordingFilter: live}).
		Narrow(context.Background(), scopedInput(catalogModels("gpt-4o", "o3", "gpt-4o-mini")))
	require.NoError(t, err)

	assert.Equal(t, []string{"gpt-4o"}, slugsOf(kept))
	assert.Equal(t, []string{"serverless", "live"}, order, "bedrock check runs before the live listing")
	assert.Equal(t, []string{"gpt-4o", "o3", "gpt-4o-mini"}, slugsOf(serverless.got.Models))
	// The second filter narrows what the first left, never the original list.
	assert.Equal(t, []string{"gpt-4o", "o3"}, slugsOf(live.got.Models))
}

func TestRegistryAvailability_PassesScopeThroughToBothFilters(t *testing.T) {
	var order []string
	in := scopedInput(catalogModels("gpt-4o"))
	serverless := &recordingFilter{name: "serverless", order: &order, answer: in.Models}
	live := &recordingFilter{name: "live", order: &order, answer: in.Models}

	_, err := appcatalog.NewRegistryAvailability(serverless, recordingLiveFilter{recordingFilter: live}).Narrow(context.Background(), in)
	require.NoError(t, err)

	for _, f := range []*recordingFilter{serverless, live} {
		assert.Equal(t, in.ProviderCode, f.got.ProviderCode, f.name)
		assert.Equal(t, in.GatewayID, f.got.GatewayID, f.name)
		assert.Equal(t, in.RegistryID, f.got.RegistryID, f.name)
	}
}

// Availability belongs to one credential set, so an unscoped listing has
// nothing to narrow against and must not reach a provider at all.
func TestRegistryAvailability_SkipsFiltersWithoutARegistryScope(t *testing.T) {
	cases := map[string]appcatalog.ServerlessFilterInput{
		"no gateway":  {ProviderCode: "openai", RegistryID: ids.New[ids.RegistryKind]()},
		"no registry": {ProviderCode: "openai", GatewayID: ids.New[ids.GatewayKind]()},
		"neither":     {ProviderCode: "openai"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			var order []string
			serverless := &recordingFilter{name: "serverless", order: &order}
			live := &recordingFilter{name: "live", order: &order}
			in.Models = catalogModels("gpt-4o", "o3")

			kept, err := appcatalog.NewRegistryAvailability(serverless, recordingLiveFilter{recordingFilter: live}).Narrow(context.Background(), in)
			require.NoError(t, err)

			require.Empty(t, order, "no filter may run without a registry to scope to")
			assert.Equal(t, []string{"gpt-4o", "o3"}, slugsOf(kept))
		})
	}
}

func TestRegistryAvailability_ReportsAVerifiedEmptyResult(t *testing.T) {
	var order []string
	serverless := &recordingFilter{name: "serverless", order: &order, answer: catalogModels("gpt-4o")}
	live := &recordingFilter{name: "live", order: &order, answer: nil}

	kept, err := appcatalog.NewRegistryAvailability(serverless, recordingLiveFilter{recordingFilter: live}).
		Narrow(context.Background(), scopedInput(catalogModels("gpt-4o")))

	require.NoError(t, err)
	assert.Empty(t, kept, "the filters own the fallback decision, the composition must not second-guess it")
}

func TestRegistryAvailability_ReturnsTheLiveListingError(t *testing.T) {
	var order []string
	serverless := &recordingFilter{name: "serverless", order: &order, answer: catalogModels("gpt-4o")}
	live := &recordingFilter{name: "live", order: &order}

	kept, err := appcatalog.NewRegistryAvailability(serverless, recordingLiveFilter{
		recordingFilter: live,
		err:             commonerrors.ErrUpstreamUnavailable,
	}).Narrow(context.Background(), scopedInput(catalogModels("gpt-4o")))

	require.ErrorIs(t, err, commonerrors.ErrUpstreamUnavailable)
	assert.Empty(t, kept)
}
