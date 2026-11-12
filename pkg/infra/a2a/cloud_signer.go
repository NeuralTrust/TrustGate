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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gcpauth"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	agentCoreService = "bedrock-agentcore"
	entraScope       = "https://ai.azure.com/.default"
	entraRefreshSkew = 5 * time.Minute
)

var _ appa2a.CloudSigner = (*CloudSigner)(nil)

// CloudSigner signs requests to hosted agents with their cloud credential:
// SigV4 for Amazon Bedrock AgentCore, a Microsoft Entra token for Foundry and
// a Google token for Vertex AI. The agent plane signs calls with it and the
// admin plane card reads, so one place decides which host gets a credential.
type CloudSigner struct {
	now             func() time.Time
	azureCredential func(*domain.AzureAuth) (azcore.TokenCredential, error)

	aws   sync.Map
	entra sync.Map

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
func (s *CloudSigner) Sign(ctx context.Context, t *domain.A2ATarget, key string, req *http.Request) error {
	host := ""
	if u, err := url.Parse(t.Endpoint()); err == nil {
		host = u.Host
	}
	if req.URL.Scheme != "https" || host == "" || !strings.EqualFold(req.URL.Host, host) {
		return fmt.Errorf("a2a: a cloud credential is sent only over https to %s", host)
	}
	c := t.CloudAuth
	switch {
	case c == nil:
		return errors.New("a2a: the agent has no cloud_auth")
	case c.AWS != nil && t.BedrockAgentCore != nil:
		return s.signV4(ctx, c.AWS, t.BedrockAgentCore.Region(), key, req)
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
func (s *CloudSigner) signV4(ctx context.Context, a *domain.A2AAWSAuth, region, key string, req *http.Request) error {
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

func (s *CloudSigner) awsCredentials(ctx context.Context, a *domain.A2AAWSAuth, region, key string) (aws.Credentials, error) {
	if v, ok := s.aws.Load(key); ok && key != "" {
		provider, _ := v.(aws.CredentialsProvider)
		return provider.Retrieve(ctx)
	}
	role := ""
	if a.UseRole {
		role = a.Role
	}
	cfg, err := bedrock.LoadAWSConfig(ctx, a.AccessKeyID, a.SecretAccessKey, a.SessionToken, region, role, a.ExternalID)
	if err != nil {
		return aws.Credentials{}, err
	}
	if key != "" {
		s.aws.Store(key, cfg.Credentials)
	}
	return cfg.Credentials.Retrieve(ctx)
}

// entraToken returns a Microsoft Entra token for Foundry, kept under key
// until five minutes before it expires.
func (s *CloudSigner) entraToken(ctx context.Context, a *domain.AzureAuth, key string) (string, error) {
	if v, ok := s.entra.Load(key); ok && key != "" {
		if tok, _ := v.(azcore.AccessToken); s.now().Add(entraRefreshSkew).Before(tok.ExpiresOn) {
			return tok.Token, nil
		}
	}
	cred, err := s.azureCredential(a)
	if err != nil {
		return "", err
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{entraScope}})
	if err != nil {
		return "", err
	}
	if key != "" {
		s.entra.Store(key, tok)
	}
	return tok.Token, nil
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
func (s *CloudSigner) googleToken(ctx context.Context, g *domain.A2AGCPAuth, key string) (string, error) {
	switch {
	case g.ServiceAccountJSON != "":
		cache := s.gcpServiceAccount
		if key == "" {
			cache = gcpauth.NewServiceAccountCache()
		}
		return cache.Token(ctx, g.ServiceAccountJSON, gcpauth.CloudPlatformScope)
	case g.ImpersonateServiceAccount != "":
		return s.gcpImpersonation.Token(ctx, g.ImpersonateServiceAccount, gcpauth.CloudPlatformScope)
	default:
		return s.gcpDefault.Token(ctx, gcpauth.CloudPlatformScope)
	}
}
