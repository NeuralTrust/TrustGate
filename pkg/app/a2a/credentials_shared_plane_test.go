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

package a2a_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingSigner struct{ calls int }

func (s *countingSigner) Sign(context.Context, *registrydomain.A2ATarget, string, *http.Request) error {
	s.calls++
	return nil
}

func cloudRegistry(t *testing.T, cloud *registrydomain.A2ACloudAuth) *registrydomain.Registry {
	t.Helper()
	reg := a2aRegistry(t, a2a.Version10, "https://travel.example/a2a")
	reg.A2ATarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.A2AAuthModeCloud}
	reg.A2ATarget.CloudAuth = cloud
	return reg
}

func gatewayCtx(dataPlane string) context.Context {
	gw := &gatewaydomain.Gateway{}
	gw.Entitlements.DataPlane = dataPlane
	return appgateway.WithGateway(context.Background(), gw)
}

func signRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://travel.example/a2a", http.NoBody)
	require.NoError(t, err)
	return req
}

var (
	explicitAzure = &registrydomain.A2ACloudAuth{Azure: &registrydomain.AzureAuth{TenantID: "tenant", ClientID: "client", ClientSecret: "s3cret"}}
	explicitGCP   = &registrydomain.A2ACloudAuth{GCP: &registrydomain.A2AGCPAuth{ServiceAccountJSON: `{"type":"service_account"}`}}
	explicitAWS   = &registrydomain.A2ACloudAuth{AWS: &registrydomain.A2AAWSAuth{AWSAuth: registrydomain.AWSAuth{AccessKeyID: "AKIA", SecretAccessKey: "secret"}}}

	ambientCloudAuths = map[string]*registrydomain.A2ACloudAuth{
		"aws default chain":       {AWS: &registrydomain.A2AAWSAuth{}},
		"aws role no external id": {AWS: &registrydomain.A2AAWSAuth{AWSAuth: registrydomain.AWSAuth{UseRole: true, Role: "arn:aws:iam::123456789012:role/tg"}}},
		"azure managed identity":  {Azure: &registrydomain.AzureAuth{UseManagedIdentity: true}},
		"gcp adc":                 {GCP: &registrydomain.A2AGCPAuth{}},
		"gcp impersonation":       {GCP: &registrydomain.A2AGCPAuth{ImpersonateServiceAccount: "sa@other.iam.gserviceaccount.com"}},
	}
)

func TestSharedDataPlaneSignRefusesAmbientCloudCredentials(t *testing.T) {
	t.Parallel()
	for name, cloud := range ambientCloudAuths {
		for ctxName, ctx := range map[string]context.Context{
			"hosted gateway":     gatewayCtx(gatewaydomain.DataPlaneHosted),
			"unspecified plane":  gatewayCtx(""),
			"no gateway in call": context.Background(),
		} {
			t.Run(name+"/"+ctxName, func(t *testing.T) {
				t.Parallel()
				signer := &countingSigner{}
				creds := a2a.NewCredentials(nil, nil, signer, false, a2a.WithSharedDataPlane())

				err := creds.Sign(ctx, cloudRegistry(t, cloud), signRequest(t))
				require.ErrorIs(t, err, registrydomain.ErrInvalidRegistry)
				assert.Zero(t, signer.calls)
			})
		}
	}
}

func TestSharedDataPlaneSignAllowsExplicitCloudCredentials(t *testing.T) {
	t.Parallel()
	for name, cloud := range map[string]*registrydomain.A2ACloudAuth{"aws": explicitAWS, "azure": explicitAzure, "gcp": explicitGCP} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			signer := &countingSigner{}
			creds := a2a.NewCredentials(nil, nil, signer, false, a2a.WithSharedDataPlane())

			require.NoError(t, creds.Sign(gatewayCtx(gatewaydomain.DataPlaneHosted), cloudRegistry(t, cloud), signRequest(t)))
			assert.Equal(t, 1, signer.calls)
		})
	}
}

func TestSignKeepsAmbientCloudCredentialsOffTheSharedDataPlane(t *testing.T) {
	t.Parallel()
	for name, cloud := range ambientCloudAuths {
		t.Run(name+"/own data plane gateway", func(t *testing.T) {
			t.Parallel()
			signer := &countingSigner{}
			creds := a2a.NewCredentials(nil, nil, signer, false, a2a.WithSharedDataPlane())

			require.NoError(t, creds.Sign(gatewayCtx(gatewaydomain.DataPlaneDedicated), cloudRegistry(t, cloud), signRequest(t)))
			assert.Equal(t, 1, signer.calls)
		})
		t.Run(name+"/self-hosted deployment", func(t *testing.T) {
			t.Parallel()
			signer := &countingSigner{}
			creds := a2a.NewCredentials(nil, nil, signer, false)

			require.NoError(t, creds.Sign(context.Background(), cloudRegistry(t, cloud), signRequest(t)))
			assert.Equal(t, 1, signer.calls)
		})
	}
}

func TestSharedDataPlaneSignRejectsAnAmbientProviderBesideAnExplicitOne(t *testing.T) {
	t.Parallel()
	signer := &countingSigner{}
	creds := a2a.NewCredentials(nil, nil, signer, false, a2a.WithSharedDataPlane())
	reg := cloudRegistry(t, &registrydomain.A2ACloudAuth{
		AWS: &registrydomain.A2AAWSAuth{AWSAuth: registrydomain.AWSAuth{AccessKeyID: "AKIA", SecretAccessKey: "secret"}},
		GCP: &registrydomain.A2AGCPAuth{},
	})

	err := creds.Sign(gatewayCtx(gatewaydomain.DataPlaneHosted), reg, signRequest(t))
	require.ErrorIs(t, err, registrydomain.ErrInvalidRegistry)
	assert.ErrorContains(t, err, "service_account_json")
	assert.Zero(t, signer.calls)
}
