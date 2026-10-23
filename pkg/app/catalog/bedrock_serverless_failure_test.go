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

package catalog

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	regmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock/controlplane"
	cpmocks "github.com/NeuralTrust/TrustGate/pkg/infra/bedrock/controlplane/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) count(substr string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, line := range strings.Split(b.buf.String(), "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type failureFixture struct {
	filter     *serverlessFilter
	client     *cpmocks.Client
	logs       *syncBuffer
	gatewayID  ids.GatewayID
	registryID ids.RegistryID
}

func newFailureFixture(t *testing.T) *failureFixture {
	t.Helper()
	finder := regmocks.NewFinder(t)
	client := cpmocks.NewClient(t)
	f := &failureFixture{
		client:     client,
		logs:       &syncBuffer{},
		gatewayID:  ids.New[ids.GatewayKind](),
		registryID: ids.New[ids.RegistryKind](),
	}
	finder.EXPECT().FindByID(mock.Anything, f.gatewayID, f.registryID).
		Return(&registrydomain.Registry{
			ID: f.registryID,
			LLMTarget: &registrydomain.LLMTarget{
				Provider: providers.ProviderBedrock,
				Auth: &registrydomain.TargetAuth{
					Type: registrydomain.AuthTypeAWS,
					AWS:  &registrydomain.AWSAuth{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s", Region: "eu-west-1"},
				},
			},
		}, nil).Maybe()
	logger := slog.New(slog.NewTextHandler(f.logs, nil))
	f.filter = NewServerlessFilter(finder, client, logger).(*serverlessFilter)
	return f
}

func (f *failureFixture) list(slugs ...string) []catalogdomain.Model {
	models := make([]catalogdomain.Model, 0, len(slugs))
	for _, s := range slugs {
		models = append(models, catalogdomain.Model{Slug: s})
	}
	return f.filter.Filter(context.Background(), ServerlessFilterInput{
		ProviderCode: providers.ProviderBedrock,
		GatewayID:    f.gatewayID,
		RegistryID:   f.registryID,
		Models:       models,
	})
}

func deniedListInferenceProfiles() error {
	return &controlplane.APIError{
		Path:   "/inference-profiles",
		Status: 403,
		Body:   `{"Message":"User: arn:aws:iam::1:user/x is not authorized to perform: bedrock:ListInferenceProfiles on resource: *"}`,
	}
}

func TestServerlessFilter_CachesControlPlaneFailureForOneMinute(t *testing.T) {
	t.Parallel()
	assert.Equal(t, time.Minute, serverlessFailureTTL)

	f := newFailureFixture(t)
	f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, mock.Anything).
		Return(controlplane.Availability{}, deniedListInferenceProfiles()).Times(3)

	// Different candidate sets: a permission failure is a property of the
	// credentials, so a catalog change must not retry it.
	assert.Len(t, f.list("a", "b"), 2)
	assert.Len(t, f.list("a", "b", "c"), 3)
	assert.Len(t, f.list("a"), 1)

	// After the window the lookup runs again: swap in a short-lived map (call 2
	// refills it, call 3 comes after it expired).
	f.filter.failures = cache.NewTTLMap(200 * time.Millisecond)
	f.list("a")
	f.list("a") // still inside the window, no call
	time.Sleep(400 * time.Millisecond)
	f.list("a")
}

func TestServerlessFilter_LogsTheFailureOnceAndNamesTheAction(t *testing.T) {
	t.Parallel()
	f := newFailureFixture(t)
	f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, mock.Anything).
		Return(controlplane.Availability{}, deniedListInferenceProfiles()).Once()

	for range 5 {
		f.list("a")
	}

	assert.Equal(t, 1, f.logs.count("availability lookup failed"), f.logs.String())
	assert.Contains(t, f.logs.String(), "missing_permission=bedrock:ListInferenceProfiles")
}

func TestServerlessFilter_DoesNotRepeatTheEntitlementWarningOnCacheHits(t *testing.T) {
	t.Parallel()
	f := newFailureFixture(t)
	f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, mock.Anything).
		Return(controlplane.Availability{
			ModelIDs:           map[string]struct{}{"a": {}},
			EntitlementChecked: false,
		}, nil).Once()

	for range 5 {
		assert.Len(t, f.list("a"), 1)
	}

	assert.Equal(t, 1, f.logs.count("could not be verified"), f.logs.String())
}

func TestServerlessFilter_CheckCatalogAccessClearsBothCachesAndReportsWarnings(t *testing.T) {
	t.Parallel()
	f := newFailureFixture(t)
	auth := &registrydomain.TargetAuth{
		Type: registrydomain.AuthTypeAWS,
		AWS:  &registrydomain.AWSAuth{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s", Region: "eu-west-1"},
	}

	f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, mock.Anything).
		Return(controlplane.Availability{}, deniedListInferenceProfiles()).Once()
	f.list("a") // primes the negative cache
	f.list("a") // served from it, no call

	f.client.EXPECT().CheckCatalogAccess(mock.Anything, mock.Anything).
		Return([]string{"bedrock:ListInferenceProfiles"}, nil).Once()
	warnings := f.filter.CheckCatalogAccess(context.Background(), providers.ProviderBedrock, auth)
	assert.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "bedrock:ListInferenceProfiles")

	// IAM fixed: the very next listing goes back to AWS instead of waiting out the TTL.
	f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, mock.Anything).
		Return(controlplane.Availability{ModelIDs: map[string]struct{}{"a": {}}, EntitlementChecked: true}, nil).Once()
	assert.Len(t, f.list("a", "b"), 1)

	// And a cached success is dropped too.
	f.client.EXPECT().CheckCatalogAccess(mock.Anything, mock.Anything).Return(nil, nil).Once()
	assert.Empty(t, f.filter.CheckCatalogAccess(context.Background(), providers.ProviderBedrock, auth))
	f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, mock.Anything).
		Return(controlplane.Availability{ModelIDs: map[string]struct{}{"a": {}, "b": {}}, EntitlementChecked: true}, nil).Once()
	assert.Len(t, f.list("a", "b"), 2)
}

func TestServerlessFilter_CheckCatalogAccessIgnoresOtherProvidersAndAuth(t *testing.T) {
	t.Parallel()
	f := newFailureFixture(t)
	assert.Nil(t, f.filter.CheckCatalogAccess(context.Background(), "openai", nil))
	assert.Nil(t, f.filter.CheckCatalogAccess(context.Background(), providers.ProviderBedrock, registrydomain.NewAPIKeyAuth("k")))
}

func TestServerlessFilter_CheckCatalogAccessReportsEveryMissingPermission(t *testing.T) {
	t.Parallel()
	f := newFailureFixture(t)
	f.client.EXPECT().CheckCatalogAccess(mock.Anything, mock.Anything).
		Return([]string{
			"bedrock:ListFoundationModels",
			"bedrock:ListInferenceProfiles",
			"bedrock:GetFoundationModelAvailability",
		}, nil).Once()

	warnings := f.filter.CheckCatalogAccess(context.Background(), providers.ProviderBedrock, &registrydomain.TargetAuth{
		Type: registrydomain.AuthTypeAWS,
		AWS:  &registrydomain.AWSAuth{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s", Region: "eu-west-1"},
	})

	assert.Len(t, warnings, 3)
}

// Only an AccessDenied 403 is a verdict about the credentials. Everything else
// is transient or unrelated to IAM, so it must be retried on the next request.
func TestServerlessFilter_DoesNotCacheTransientOrNonPermissionFailures(t *testing.T) {
	t.Parallel()
	cases := map[string]error{
		"cancelled":          context.Canceled,
		"deadline":           context.DeadlineExceeded,
		"server error":       &controlplane.APIError{Path: "/foundation-models", Status: 503, Body: "unavailable"},
		"throttled":          &controlplane.APIError{Path: "/foundation-models", Status: 429, Body: "slow down"},
		"credential failure": errors.New("bedrock controlplane: retrieve aws credentials: boom"),
		"bad token 403": &controlplane.APIError{Path: "/foundation-models", Status: 403,
			Body: `{"__type":"UnrecognizedClientException","message":"The security token included in the request is invalid."}`},
	}
	for name, failure := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFailureFixture(t)
			f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, mock.Anything).
				Return(controlplane.Availability{}, failure).Twice()

			assert.Len(t, f.list("a"), 1)
			assert.Len(t, f.list("a"), 1)
		})
	}
}

// A positive verdict for the exact candidate set is not shadowed by a failure
// remembered for the same credentials.
func TestServerlessFilter_FailureDoesNotShadowAPositiveVerdict(t *testing.T) {
	t.Parallel()
	f := newFailureFixture(t)
	f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, []string{"a", "b"}).
		Return(controlplane.Availability{ModelIDs: map[string]struct{}{"a": {}}, EntitlementChecked: true}, nil).Once()
	f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, []string{"a", "c"}).
		Return(controlplane.Availability{}, deniedListInferenceProfiles()).Once()

	assert.Len(t, f.list("a", "b"), 1)
	assert.Len(t, f.list("a", "c"), 2) // fails, remembered per credentials
	assert.Len(t, f.list("a", "b"), 1) // the cached positive still narrows
}

// A lookup that was in flight while test-connection cleared the caches must not
// write its stale answer back afterwards.
func TestServerlessFilter_FillOverlappedByAClearIsDropped(t *testing.T) {
	t.Parallel()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f := newFailureFixture(t)
		f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, mock.Anything).
			RunAndReturn(func(context.Context, controlplane.Credentials, []string) (controlplane.Availability, error) {
				f.clearCaches()
				return controlplane.Availability{ModelIDs: map[string]struct{}{"a": {}}, EntitlementChecked: true}, nil
			}).Twice()
		f.list("a")
		f.list("a")
	})
	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		f := newFailureFixture(t)
		f.client.EXPECT().ListInvocableModelIDs(mock.Anything, mock.Anything, mock.Anything).
			RunAndReturn(func(context.Context, controlplane.Credentials, []string) (controlplane.Availability, error) {
				f.clearCaches()
				return controlplane.Availability{}, deniedListInferenceProfiles()
			}).Twice()
		f.list("a")
		f.list("a")
	})
}

func (f *failureFixture) clearCaches() {
	creds := controlplane.Credentials{Region: "eu-west-1", AccessKey: "AKIAEXAMPLE", SecretKey: "s"}
	f.filter.cache.DeleteByPrefix(creds.CacheKey() + "|")
	f.filter.failures.Delete(creds.CacheKey())
}
