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

package bedrockguardrail

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

type fakeGuardrailClient struct{}

func (fakeGuardrailClient) ApplyGuardrail(
	context.Context,
	*bedrockruntime.ApplyGuardrailInput,
	...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	return &bedrockruntime.ApplyGuardrailOutput{}, nil
}

func baseCredentials() awsCredentials {
	return awsCredentials{
		region:          "us-east-1",
		useRole:         false,
		roleARN:         "",
		sessionName:     "session",
		accessKeyID:     "AKIAEXAMPLE",
		secretAccessKey: "secret",
		sessionToken:    "token",
	}
}

func TestFingerprintStableForIdenticalCredentials(t *testing.T) {
	a := baseCredentials()
	b := baseCredentials()
	if a.fingerprint() != b.fingerprint() {
		t.Fatalf("expected identical credentials to produce identical fingerprints")
	}
}

func TestFingerprintDiffersPerField(t *testing.T) {
	base := baseCredentials()
	mutators := map[string]func(*awsCredentials){
		"region":          func(c *awsCredentials) { c.region = "eu-west-1" },
		"useRole":         func(c *awsCredentials) { c.useRole = true },
		"roleARN":         func(c *awsCredentials) { c.roleARN = "arn:aws:iam::123:role/x" },
		"sessionName":     func(c *awsCredentials) { c.sessionName = "other" },
		"accessKeyID":     func(c *awsCredentials) { c.accessKeyID = "AKIAOTHER" },
		"secretAccessKey": func(c *awsCredentials) { c.secretAccessKey = "other-secret" },
		"sessionToken":    func(c *awsCredentials) { c.sessionToken = "other-token" },
	}
	baseFP := base.fingerprint()
	for name, mutate := range mutators {
		mutated := base
		mutate(&mutated)
		if mutated.fingerprint() == baseFP {
			t.Errorf("expected fingerprint to change when %s differs", name)
		}
	}
}

func TestFingerprintAvoidsFieldBoundaryCollision(t *testing.T) {
	a := awsCredentials{accessKeyID: "ab", secretAccessKey: "c"}
	b := awsCredentials{accessKeyID: "a", secretAccessKey: "bc"}
	if a.fingerprint() == b.fingerprint() {
		t.Fatalf("expected distinct field boundaries to produce distinct fingerprints")
	}
}

func TestCredentialsFromConfigMapsAllFields(t *testing.T) {
	cfg := Credentials{
		AWSRegion:       "eu-west-1",
		UseRole:         true,
		RoleARN:         "arn:aws:iam::123:role/x",
		SessionName:     "session",
		AccessKeyID:     "AKIAEXAMPLE",
		SecretAccessKey: "secret",
		SessionToken:    "token",
	}
	got := credentialsFromConfig(cfg)
	want := awsCredentials{
		region:          "eu-west-1",
		useRole:         true,
		roleARN:         "arn:aws:iam::123:role/x",
		sessionName:     "session",
		accessKeyID:     "AKIAEXAMPLE",
		secretAccessKey: "secret",
		sessionToken:    "token",
	}
	if got != want {
		t.Fatalf("credentialsFromConfig mismatch: got %+v want %+v", got, want)
	}
}

func TestNewCachedGuardrailClientWiresBuildSeam(t *testing.T) {
	g := newCachedGuardrailClient()
	if g == nil || g.cache == nil {
		t.Fatalf("expected non-nil cached client and cache")
	}
	if g.cache.build == nil {
		t.Fatalf("expected build seam to be wired")
	}
}

func TestClientCacheSingleFlight(t *testing.T) {
	var builds atomic.Int64
	cache := &clientCache{
		build: func(context.Context, awsCredentials) (guardrailClient, error) {
			builds.Add(1)
			return fakeGuardrailClient{}, nil
		},
	}

	const goroutines = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	creds := baseCredentials()
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			client, err := cache.get(context.Background(), creds)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if client == nil {
				t.Errorf("expected non-nil client")
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := builds.Load(); got != 1 {
		t.Fatalf("expected build to be called exactly once, got %d", got)
	}
}

func TestClientCacheDoesNotCacheFailedBuild(t *testing.T) {
	var builds atomic.Int64
	buildErr := errors.New("boom")
	cache := &clientCache{
		build: func(context.Context, awsCredentials) (guardrailClient, error) {
			if builds.Add(1) == 1 {
				return nil, buildErr
			}
			return fakeGuardrailClient{}, nil
		},
	}

	creds := baseCredentials()
	if _, err := cache.get(context.Background(), creds); !errors.Is(err, buildErr) {
		t.Fatalf("expected first get to return build error, got %v", err)
	}

	client, err := cache.get(context.Background(), creds)
	if err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if client == nil {
		t.Fatalf("expected non-nil client on retry")
	}
	if got := builds.Load(); got != 2 {
		t.Fatalf("expected build to be retried (2 calls), got %d", got)
	}
}

func TestCachedGuardrailClientReusesBuiltClient(t *testing.T) {
	var builds atomic.Int64
	g := &cachedGuardrailClient{
		cache: &clientCache{
			build: func(context.Context, awsCredentials) (guardrailClient, error) {
				builds.Add(1)
				return fakeGuardrailClient{}, nil
			},
		},
	}

	creds := baseCredentials()
	for range 3 {
		if _, err := g.ApplyGuardrail(context.Background(), creds, &bedrockruntime.ApplyGuardrailInput{}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if got := builds.Load(); got != 1 {
		t.Fatalf("expected build once across reused calls, got %d", got)
	}
}
