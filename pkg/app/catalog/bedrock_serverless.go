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
}

var _ ServerlessFilter = (*serverlessFilter)(nil)

type serverlessFilter struct {
	finder appregistry.Finder
	client controlplane.Client
	cache  *cache.TTLMap
	logger *slog.Logger
}

func NewServerlessFilter(
	finder appregistry.Finder,
	client controlplane.Client,
	logger *slog.Logger,
) ServerlessFilter {
	return &serverlessFilter{
		finder: finder,
		client: client,
		cache:  cache.NewTTLMap(serverlessCacheTTL),
		logger: logger,
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

	availability, err := f.availability(ctx, creds, slugs)
	if err != nil {
		f.logger.Warn("bedrock availability lookup failed, listing unfiltered catalog",
			slog.String("registry_id", in.RegistryID.String()),
			slog.String("region", creds.Region),
			slog.String("error", err.Error()))
		return in.Models
	}
	if !availability.EntitlementChecked {
		f.logger.Warn("bedrock model access could not be verified; catalog may list models the account cannot invoke",
			slog.String("registry_id", in.RegistryID.String()),
			slog.String("region", creds.Region),
			slog.String("hint", "grant bedrock:GetFoundationModelAvailability to these credentials"))
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

func (f *serverlessFilter) availability(
	ctx context.Context,
	creds controlplane.Credentials,
	candidates []string,
) (controlplane.Availability, error) {
	key := availabilityCacheKey(creds, candidates)
	if cached, ok := f.cache.Get(key); ok {
		if availability, ok := cached.(controlplane.Availability); ok {
			return availability, nil
		}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, serverlessLookupTimeout)
	defer cancel()

	availability, err := f.client.ListInvocableModelIDs(lookupCtx, creds, candidates)
	if err != nil {
		return controlplane.Availability{}, err
	}
	f.cache.Set(key, availability)
	return availability, nil
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
