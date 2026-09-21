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

package vertex

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gcpauth"
)

var defaultTokenCache = newTokenCache()

type tokenSource func(context.Context, *providers.GCP) (string, error)

// tokenCache adapts a provider connection's service-account JSON credentials
// to gcpauth.ServiceAccountCache, which does the actual JWT-to-bearer-token
// exchange and per-credential caching. The cache is shared machinery (see
// pkg/infra/providers/gcpauth), kept here so callers that already depend on
// providers.GCP do not need to know about gcpauth themselves.
type tokenCache struct {
	cache *gcpauth.ServiceAccountCache
}

func newTokenCache() *tokenCache {
	return &tokenCache{cache: gcpauth.NewServiceAccountCache()}
}

func (c *tokenCache) token(ctx context.Context, gcp *providers.GCP) (string, error) {
	if gcp == nil || gcp.ServiceAccountJSON == "" {
		return "", fmt.Errorf("gcp service account credentials are required for Vertex AI")
	}
	return c.cache.Token(ctx, gcp.ServiceAccountJSON, gcpauth.CloudPlatformScope)
}
