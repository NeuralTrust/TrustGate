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

package a2a

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretref"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gcpauth"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"golang.org/x/sync/singleflight"
)

const (
	agentCoreService = "bedrock-agentcore"
	entraScope       = "https://ai.azure.com/.default"
	entraRefreshSkew = 5 * time.Minute
	// credentialTimeout bounds a credential fetch that several calls share,
	// which runs apart from the context of the call that started it.
	credentialTimeout = 30 * time.Second
)

var _ appa2a.CloudSigner = (*CloudSigner)(nil)

// CloudSigner signs requests to hosted agents with their cloud credential:
// SigV4 for Amazon Bedrock AgentCore, a Microsoft Entra token for Foundry and
// a Google token for Vertex AI. The agent plane signs calls with it and the
// admin plane card reads, so one place decides which host gets a credential.
type CloudSigner struct {
	now             func() time.Time
	azureCredential func(*domain.AzureAuth) (azcore.TokenCredential, error)

	aws    versioned[aws.CredentialsProvider]
	entra  versioned[azcore.AccessToken]
	flight singleflight.Group

	gcpServiceAccount *gcpauth.ServiceAccountCache
	gcpImpersonation  *gcpauth.ImpersonationCache
	gcpDefault        *gcpauth.ApplicationDefaultCache
}

// NewCloudSigner returns a signer with empty credential caches.
func NewCloudSigner() *CloudSigner {
	adc := gcpauth.NewApplicationDefaultCache()
	return &CloudSigner{
		now:               time.Now,
		azureCredential:   azureCredential,
		gcpServiceAccount: gcpauth.NewServiceAccountCache(),
		gcpImpersonation:  gcpauth.NewImpersonationCache(adc),
		gcpDefault:        adc,
	}
}

// Sign sets the credential of t.CloudAuth on req.
func (s *CloudSigner) Sign(ctx context.Context, t *domain.A2ATarget, key appa2a.CacheKey, req *http.Request) error {
	host := ""
	if u, err := url.Parse(t.Endpoint()); err == nil {
		host = u.Host
	}
	if req.URL.Scheme != "https" || host == "" || !strings.EqualFold(req.URL.Host, host) {
		return fmt.Errorf("a2a: a cloud credential is sent only over https to %s", host)
	}
	c := t.CloudAuth
	if cloudAuthHoldsReference(c) {
		return errors.New("a2a: cloud_auth holds a secret reference, which is not resolved there")
	}
	switch {
	case c == nil:
		return errors.New("a2a: the agent has no cloud_auth")
	case c.AWS != nil && t.AWSRegion() != "":
		return s.signV4(ctx, c.AWS, t.AWSRegion(), key, req)
	case c.Azure != nil:
		token, err := s.entraToken(ctx, c.Azure, key)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	case c.GCP != nil:
		token, err := s.googleToken(ctx, c.GCP, key)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
	return errors.New("a2a: cloud_auth does not match the agent's provider")
}

// signV4 signs req with SigV4 for the AgentCore service of region, over the
// exact body it carries.
func (s *CloudSigner) signV4(ctx context.Context, a *domain.A2AAWSAuth, region string, key appa2a.CacheKey, req *http.Request) error {
	creds, err := s.awsCredentials(ctx, a, region, key)
	if err != nil {
		return err
	}
	var body []byte
	if req.GetBody != nil {
		r, err := req.GetBody()
		if err != nil {
			return err
		}
		if body, err = io.ReadAll(r); err != nil {
			return err
		}
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", hash)
	return v4.NewSigner().SignHTTP(ctx, creds, req, hash, agentCoreService, region, s.now())
}

func (s *CloudSigner) awsCredentials(ctx context.Context, a *domain.A2AAWSAuth, region string, key appa2a.CacheKey) (aws.Credentials, error) {
	if provider, ok := s.aws.load(key); ok {
		return provider.Retrieve(ctx)
	}
	load := func(ctx context.Context) (aws.CredentialsProvider, error) {
		role := ""
		if a.UseRole {
			role = a.Role
		}
		cfg, err := bedrock.LoadAWSConfig(ctx, a.AccessKeyID, a.SecretAccessKey, a.SessionToken, region, role, a.ExternalID)
		if err != nil {
			return nil, err
		}
		return cfg.Credentials, nil
	}
	if key.IsZero() {
		provider, err := load(ctx)
		if err != nil {
			return aws.Credentials{}, err
		}
		return provider.Retrieve(ctx)
	}
	provider, err := shared(ctx, &s.flight, "aws|"+key.Registry+"|"+key.Version, func(ctx context.Context) (aws.CredentialsProvider, error) {
		if provider, ok := s.aws.load(key); ok {
			return provider, nil
		}
		provider, err := load(ctx)
		if err != nil {
			return nil, err
		}
		s.aws.store(key, provider)
		return provider, nil
	})
	if err != nil {
		return aws.Credentials{}, err
	}
	return provider.Retrieve(ctx)
}

// entraToken returns a Microsoft Entra token for Foundry, kept under key
// until five minutes before it expires.
func (s *CloudSigner) entraToken(ctx context.Context, a *domain.AzureAuth, key appa2a.CacheKey) (string, error) {
	fresh := func(tok azcore.AccessToken) bool { return s.now().Add(entraRefreshSkew).Before(tok.ExpiresOn) }
	if tok, ok := s.entra.load(key); ok && fresh(tok) {
		return tok.Token, nil
	}
	get := func(ctx context.Context) (azcore.AccessToken, error) {
		cred, err := s.azureCredential(a)
		if err != nil {
			return azcore.AccessToken{}, err
		}
		return cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{entraScope}})
	}
	if key.IsZero() {
		tok, err := get(ctx)
		return tok.Token, err
	}
	tok, err := shared(ctx, &s.flight, "entra|"+key.Registry+"|"+key.Version, func(ctx context.Context) (azcore.AccessToken, error) {
		if tok, ok := s.entra.load(key); ok && fresh(tok) {
			return tok, nil
		}
		tok, err := get(ctx)
		if err != nil {
			return azcore.AccessToken{}, err
		}
		s.entra.store(key, tok)
		return tok, nil
	})
	return tok.Token, err
}

// shared runs fetch once for every call waiting on name, apart from the
// context of the call that started it so that one caller leaving does not
// fail the others.
func shared[T any](ctx context.Context, flight *singleflight.Group, name string, fetch func(context.Context) (T, error)) (T, error) {
	v, err, _ := flight.Do(name, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialTimeout)
		defer cancel()
		return fetch(ctx)
	})
	if err != nil {
		var zero T
		return zero, err
	}
	out, _ := v.(T)
	return out, nil
}

// versioned keeps one value per registry, tagged with the registry version it
// was made for. A value of another version is not returned and is replaced
// by the next store, so a registry that changes many times keeps one entry.
type versioned[T any] struct {
	m sync.Map
}

type versionedEntry[T any] struct {
	version string
	value   T
}

func (v *versioned[T]) load(key appa2a.CacheKey) (T, bool) {
	var zero T
	if key.IsZero() {
		return zero, false
	}
	raw, ok := v.m.Load(key.Registry)
	if !ok {
		return zero, false
	}
	e, _ := raw.(versionedEntry[T])
	if e.version != key.Version {
		return zero, false
	}
	return e.value, true
}

func (v *versioned[T]) store(key appa2a.CacheKey, value T) {
	if key.IsZero() {
		return
	}
	v.m.Store(key.Registry, versionedEntry[T]{version: key.Version, value: value})
}

func azureCredential(a *domain.AzureAuth) (azcore.TokenCredential, error) {
	if a.UseManagedIdentity {
		return azidentity.NewDefaultAzureCredential(nil)
	}
	return azidentity.NewClientSecretCredential(a.TenantID, a.ClientID, a.ClientSecret, nil)
}

// googleToken returns a Google token of scope cloud-platform from a
// service-account key, an impersonated service account, or the pod's
// Application Default Credentials. With an empty key the service-account key
// is not kept.
func (s *CloudSigner) googleToken(ctx context.Context, g *domain.A2AGCPAuth, key appa2a.CacheKey) (string, error) {
	switch {
	case g.ServiceAccountJSON != "":
		cache := s.gcpServiceAccount
		if key.IsZero() {
			cache = gcpauth.NewServiceAccountCache()
		}
		return cache.Token(ctx, g.ServiceAccountJSON, gcpauth.CloudPlatformScope)
	case g.ImpersonateServiceAccount != "":
		return s.gcpImpersonation.Token(ctx, g.ImpersonateServiceAccount, gcpauth.CloudPlatformScope)
	default:
		return s.gcpDefault.Token(ctx, gcpauth.CloudPlatformScope)
	}
}

// cloudAuthHoldsReference reports whether a cloud credential is reference
// shaped. cloud_auth is not a declared location, so such a value is never
// resolved and must not reach the cloud provider as a literal credential.
func cloudAuthHoldsReference(c *domain.A2ACloudAuth) bool {
	if c == nil {
		return false
	}
	var values []string
	if c.AWS != nil {
		values = append(values, c.AWS.AccessKeyID, c.AWS.SecretAccessKey, c.AWS.SessionToken)
	}
	if c.Azure != nil {
		values = append(values, c.Azure.APIKey, c.Azure.ClientSecret)
	}
	if c.GCP != nil {
		values = append(values, c.GCP.ServiceAccountJSON)
	}
	for _, v := range values {
		if secretref.IsRef(v) {
			return true
		}
	}
	return false
}
