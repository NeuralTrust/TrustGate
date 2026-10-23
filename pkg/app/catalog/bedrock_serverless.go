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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock/controlplane"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	// serverlessCacheTTL keeps one control plane round trip out of every model
	// picker render. AWS adds models on the order of weeks, so a few minutes of
	// staleness costs nothing.
	serverlessCacheTTL = 10 * time.Minute
	// serverlessFailureTTL is how long a control plane failure is remembered. A
	// missing IAM permission does not fix itself between two page renders, so
	// retrying three AWS calls on every model-list request only adds latency and
	// log noise; but the customer who just granted it must not wait long, so the
	// window is short (and test-connection clears it outright).
	serverlessFailureTTL = time.Minute
	// serverlessLookupTimeout bounds the two control plane GETs so a slow or
	// unreachable AWS endpoint cannot hold the admin API request open.
	serverlessLookupTimeout = 8 * time.Second
)

// ServerlessFilterInput carries what narrowing a catalog listing needs: the
// provider being listed, the registry whose credentials decide availability,
// and the models to narrow.
type ServerlessFilterInput struct {
	ProviderCode string
	GatewayID    ids.GatewayID
	RegistryID   ids.RegistryID
	Models       []domain.Model
}

//go:generate mockery --name=ServerlessFilter --dir=. --output=./mocks --filename=catalog_serverless_filter_mock.go --case=underscore --with-expecter
type ServerlessFilter interface {
	// Filter narrows models to the ones a registry's credentials can actually
	// invoke: serverless, in the registry's region, and with model access granted
	// to the account.
	//
	// It never returns an error. Any provider other than Bedrock, any non-AWS
	// auth, and any control plane failure yield the input unchanged, since a
	// too-long list degrades gracefully while a spuriously empty one does not.
	// A verified empty result, on the other hand, is passed through as empty.
	Filter(ctx context.Context, in ServerlessFilterInput) []domain.Model

	// CheckCatalogAccess drops everything cached for these credentials, positive
	// and negative, then probes the control plane permissions catalog narrowing
	// needs. It returns one human-readable warning per denied permission, or nil
	// when all are granted or the provider is not Bedrock with AWS credentials.
	CheckCatalogAccess(ctx context.Context, provider string, auth *registrydomain.TargetAuth) []string
}

var _ ServerlessFilter = (*serverlessFilter)(nil)

type serverlessFilter struct {
	finder appregistry.Finder
	client controlplane.Client
	cache  *cache.TTLMap
	// failures remembers control plane errors per credential set, apart from
	// cache because TTLMap has a single TTL per map.
	failures *cache.TTLMap
	logger   *slog.Logger
}

func NewServerlessFilter(
	finder appregistry.Finder,
	client controlplane.Client,
	logger *slog.Logger,
) ServerlessFilter {
	return &serverlessFilter{
		finder:   finder,
		client:   client,
		cache:    cache.NewTTLMap(serverlessCacheTTL),
		failures: cache.NewTTLMap(serverlessFailureTTL),
		logger:   logger,
	}
}

func (f *serverlessFilter) Filter(ctx context.Context, in ServerlessFilterInput) []domain.Model {
	if in.ProviderCode != providers.ProviderBedrock || len(in.Models) == 0 {
		return in.Models
	}

	creds, err := f.credentials(ctx, in.GatewayID, in.RegistryID)
	if err != nil {
		f.logger.Debug("bedrock serverless filter skipped",
			slog.String("registry_id", in.RegistryID.String()),
			slog.String("error", err.Error()))
		return in.Models
	}

	slugs := make([]string, 0, len(in.Models))
	for _, model := range in.Models {
		slugs = append(slugs, model.Slug)
	}

	// The failure and entitlement warnings are logged by availability, once per
	// fresh lookup: a cached verdict repeats on every request and must stay quiet.
	availability, err := f.availability(ctx, in.RegistryID, creds, slugs)
	if err != nil {
		return in.Models
	}

	kept := make([]domain.Model, 0, len(availability.ModelIDs))
	for _, model := range in.Models {
		if _, ok := availability.ModelIDs[model.Slug]; ok {
			kept = append(kept, model)
		}
	}

	// An empty result is reported as-is once entitlement was verified: the
	// account really can invoke none of these models, and offering them anyway
	// would only move the failure to request time. Without a verdict the same
	// emptiness may just mean the catalog slugs and AWS disagree, so fall back.
	if len(kept) == 0 && !availability.EntitlementChecked {
		f.logger.Warn("no catalog model matched bedrock model ids, listing unfiltered catalog",
			slog.String("registry_id", in.RegistryID.String()),
			slog.String("region", creds.Region))
		return in.Models
	}
	if len(kept) == 0 {
		f.logger.Warn("no bedrock model is invocable with these credentials",
			slog.String("registry_id", in.RegistryID.String()),
			slog.String("region", creds.Region),
			slog.String("hint", "enable model access for this account in the Bedrock console"))
		return kept
	}

	f.logger.Debug("bedrock catalog narrowed to invocable models",
		slog.String("registry_id", in.RegistryID.String()),
		slog.String("region", creds.Region),
		slog.Int("before", len(in.Models)),
		slog.Int("after", len(kept)))
	return kept
}

func (f *serverlessFilter) credentials(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) (controlplane.Credentials, error) {
	if registryID.IsNil() || gatewayID.IsNil() {
		return controlplane.Credentials{}, fmt.Errorf("gateway and registry ids are required")
	}
	reg, err := f.finder.FindByID(ctx, gatewayID, registryID)
	if err != nil {
		return controlplane.Credentials{}, fmt.Errorf("find registry: %w", err)
	}
	if reg.Provider() != providers.ProviderBedrock {
		return controlplane.Credentials{}, fmt.Errorf("registry provider is %q, not bedrock", reg.Provider())
	}
	auth := reg.Auth()
	if auth == nil || auth.Type != registrydomain.AuthTypeAWS || auth.AWS == nil {
		return controlplane.Credentials{}, fmt.Errorf("registry has no aws credentials")
	}
	return controlplane.Credentials{
		Region:       auth.AWS.Region,
		AccessKey:    auth.AWS.AccessKeyID,
		SecretKey:    auth.AWS.SecretAccessKey,
		SessionToken: auth.AWS.SessionToken,
		UseRole:      auth.AWS.UseRole,
		RoleARN:      auth.AWS.Role,
	}, nil
}

// availability returns the verdict for the candidates.
//
// Lookup order: the success cache first, then the failure cache. A verdict for
// the exact candidate set was computed with working credentials, so a failure
// remembered for the same credentials (from another candidate set, or an IAM
// change in between) must not shadow it; the failure entry only answers when
// nothing more specific is cached.
//
// Only an AccessDenied 403 is remembered. It is a verdict on the credentials'
// IAM policy, which will not change by itself within the window. Cancellation,
// deadlines, network errors, 5xx, throttling and credential or STS failures say
// nothing durable and are retried on the next request.
//
// Both maps are written with the generation read before the lookup, so a fill
// that overlapped a CheckCatalogAccess clear is dropped instead of putting a
// stale verdict back. Warnings are logged only when a lookup actually ran.
func (f *serverlessFilter) availability(
	ctx context.Context,
	registryID ids.RegistryID,
	creds controlplane.Credentials,
	candidates []string,
) (controlplane.Availability, error) {
	key := availabilityCacheKey(creds, candidates)
	failureKey := creds.CacheKey()
	if cached, ok := f.cache.Get(key); ok {
		if availability, ok := cached.(controlplane.Availability); ok {
			return availability, nil
		}
	}
	if cached, ok := f.failures.Get(failureKey); ok {
		if failure, ok := cached.(availabilityFailure); ok {
			return controlplane.Availability{}, failure.err
		}
	}

	successGen := f.cache.Generation()
	failureGen := f.failures.Generation()

	lookupCtx, cancel := context.WithTimeout(ctx, serverlessLookupTimeout)
	defer cancel()

	availability, err := f.client.ListInvocableModelIDs(lookupCtx, creds, candidates)
	if err != nil {
		attrs := []any{
			slog.String("registry_id", registryID.String()),
			slog.String("region", creds.Region),
			slog.String("error", err.Error()),
		}
		if action, denied := controlplane.MissingPermission(err); denied {
			f.failures.SetIfGeneration(failureKey, availabilityFailure{err: err}, failureGen)
			if action != "" {
				attrs = append(attrs,
					slog.String("missing_permission", action),
					slog.String("hint", "grant "+action+" to these credentials; the model list stays unfiltered meanwhile"))
			}
		}
		f.logger.Warn("bedrock availability lookup failed, listing unfiltered catalog", attrs...)
		return controlplane.Availability{}, err
	}
	f.cache.SetIfGeneration(key, availability, successGen)
	if !availability.EntitlementChecked {
		f.logger.Warn("bedrock model access could not be verified; catalog may list models the account cannot invoke",
			slog.String("registry_id", registryID.String()),
			slog.String("region", creds.Region),
			slog.String("hint", "grant bedrock:GetFoundationModelAvailability to these credentials"))
	}
	return availability, nil
}

// availabilityFailure is the negative cache entry; the typed wrapper tells it
// apart from an Availability in the shared any-valued map.
type availabilityFailure struct{ err error }

func (f *serverlessFilter) CheckCatalogAccess(
	ctx context.Context,
	provider string,
	auth *registrydomain.TargetAuth,
) []string {
	if provider != providers.ProviderBedrock || auth == nil || auth.Type != registrydomain.AuthTypeAWS || auth.AWS == nil {
		return nil
	}
	creds := controlplane.Credentials{
		Region:       auth.AWS.Region,
		AccessKey:    auth.AWS.AccessKeyID,
		SecretKey:    auth.AWS.SecretAccessKey,
		SessionToken: auth.AWS.SessionToken,
		UseRole:      auth.AWS.UseRole,
		RoleARN:      auth.AWS.Role,
	}
	// Whoever tests a connection has usually just edited IAM: show them the new
	// state now, not after the success or failure TTL.
	f.cache.DeleteByPrefix(creds.CacheKey() + "|")
	f.failures.Delete(creds.CacheKey())

	lookupCtx, cancel := context.WithTimeout(ctx, serverlessLookupTimeout)
	defer cancel()
	missing, err := f.client.CheckCatalogAccess(lookupCtx, creds)
	if err != nil {
		f.logger.Debug("bedrock catalog access check failed",
			slog.String("region", creds.Region),
			slog.String("error", err.Error()))
		return []string{"Catalog permissions could not be checked; the model list may include models this account cannot invoke."}
	}
	warnings := make([]string, 0, len(missing))
	for _, action := range missing {
		warnings = append(warnings, fmt.Sprintf(
			"Missing IAM permission %s: the model list cannot be narrowed to the models this account can invoke, so it shows the full catalog. Invoking models is unaffected.",
			action))
	}
	return warnings
}

// availabilityCacheKey scopes a cached verdict to both the credentials and the
// exact candidate set, so a catalog sync that adds or drops models is not served
// a stale answer computed for the previous list.
func availabilityCacheKey(creds controlplane.Credentials, candidates []string) string {
	sorted := slices.Clone(candidates)
	slices.Sort(sorted)
	digest := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return creds.CacheKey() + "|" + hex.EncodeToString(digest[:8])
}
