// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package secretstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

type fakeBackend struct {
	probeErr error
	fetchErr error
	secret   domain.Secret
	fetched  []string
}

func (b *fakeBackend) Probe(context.Context) error { return b.probeErr }

func (b *fakeBackend) Fetch(_ context.Context, path, version string) (domain.Secret, error) {
	b.fetched = append(b.fetched, path+"@"+version)
	return b.secret, b.fetchErr
}

type oneStore struct {
	store   *domain.Store
	backend domain.Backend
}

func (c oneStore) Get(name string) (*domain.Store, domain.Backend, bool) {
	if strings.EqualFold(name, c.store.Name) {
		return c.store, c.backend, true
	}
	return nil, nil, false
}
func (c oneStore) Stores() []*domain.Store { return []*domain.Store{c.store} }
func (c oneStore) LoadError() error        { return nil }

func TestTester(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	other := ids.New[ids.GatewayKind]()
	const value = "sk-the-secret-value"
	newTester := func(st *domain.Store, b *fakeBackend) Tester {
		return NewTester(TesterConfig{Catalog: oneStore{store: st, backend: b}, Eligibility: domain.EligibilityAll})
	}
	vaultStore := func(gateways ...ids.GatewayID) *domain.Store {
		return &domain.Store{Name: "corp-vault", Type: domain.TypeHashiCorpVault, AllowedPaths: []string{"ai-gateway/"}, Gateways: gateways}
	}

	t.Run("reads the path and reports the version, never the value", func(t *testing.T) {
		b := &fakeBackend{secret: domain.NewFieldsSecret(map[string]string{"api_key": value}, "3")}
		res, err := newTester(vaultStore(), b).Test(context.Background(), TestInput{GatewayID: gwID, Store: "CORP-VAULT", Path: "ai-gateway/openai", Field: "api_key"})
		if err != nil || res.Auth != OutcomeOK || res.Read != OutcomeOK || res.Version != "3" {
			t.Fatalf("Test = %+v, %v", res, err)
		}
		if strings.Contains(fmt.Sprintf("%+v", res), value) {
			t.Fatal("the result holds the secret value")
		}
	})
	t.Run("without a path only authenticates", func(t *testing.T) {
		b := &fakeBackend{}
		res, err := newTester(vaultStore(), b).Test(context.Background(), TestInput{GatewayID: gwID, Store: "corp-vault"})
		if err != nil || res.Auth != OutcomeOK || res.Read != OutcomeSkipped || len(b.fetched) != 0 {
			t.Fatalf("Test = %+v, %v, fetched %v", res, err, b.fetched)
		}
	})
	t.Run("failed authentication skips the read", func(t *testing.T) {
		b := &fakeBackend{probeErr: fmt.Errorf("login: %w", domain.ErrAuthFailed)}
		res, err := newTester(vaultStore(), b).Test(context.Background(), TestInput{GatewayID: gwID, Store: "corp-vault", Path: "ai-gateway/openai"})
		if err != nil || res.Auth != string(domain.ClassAuthFailed) || res.Read != OutcomeSkipped || len(b.fetched) != 0 {
			t.Fatalf("Test = %+v, %v", res, err)
		}
	})
	t.Run("store answers are results", func(t *testing.T) {
		b := &fakeBackend{fetchErr: domain.ErrNotFound}
		res, err := newTester(vaultStore(), b).Test(context.Background(), TestInput{GatewayID: gwID, Store: "corp-vault", Path: "ai-gateway/missing"})
		if err != nil || res.Read != string(domain.ClassNotFound) {
			t.Fatalf("Test = %+v, %v", res, err)
		}
		b = &fakeBackend{secret: domain.NewFieldsSecret(map[string]string{"api_key": value}, "")}
		res, _ = newTester(vaultStore(), b).Test(context.Background(), TestInput{GatewayID: gwID, Store: "corp-vault", Path: "ai-gateway/openai", Field: "nope"})
		if res.Read != string(domain.ClassFieldNotFound) {
			t.Fatalf("Read = %q, want field_not_found", res.Read)
		}
	})

	refusals := []struct {
		name string
		st   *domain.Store
		in   TestInput
		want error
	}{
		{"unknown store", vaultStore(), TestInput{GatewayID: gwID, Store: "other"}, refdomain.ErrUnknownStore},
		{"allowlist excludes the gateway", vaultStore(other), TestInput{GatewayID: gwID, Store: "corp-vault"}, refdomain.ErrUnknownStore},
		{"path outside the allowed prefixes", vaultStore(), TestInput{GatewayID: gwID, Store: "corp-vault", Path: "prod/db"}, refdomain.ErrPathNotAllowed},
		{"path traversal", vaultStore(), TestInput{GatewayID: gwID, Store: "corp-vault", Path: "ai-gateway/../prod"}, refdomain.ErrInvalidReference},
		{"empty segment", vaultStore(), TestInput{GatewayID: gwID, Store: "corp-vault", Path: "ai-gateway//x"}, refdomain.ErrInvalidReference},
		{"field without path", vaultStore(), TestInput{GatewayID: gwID, Store: "corp-vault", Field: "k"}, refdomain.ErrInvalidReference},
		{"version on a file store", &domain.Store{Name: "files", Type: domain.TypeFile, AllowedPaths: []string{domain.AllPaths}}, TestInput{GatewayID: gwID, Store: "files", Path: "openai", Version: "2"}, refdomain.ErrInvalidReference},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			b := &fakeBackend{}
			_, err := newTester(tc.st, b).Test(context.Background(), tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if len(b.fetched) != 0 {
				t.Fatal("a refused test reached the store")
			}
		})
	}

	t.Run("a plane without stores", func(t *testing.T) {
		_, err := NewTester(TesterConfig{}).Test(context.Background(), TestInput{GatewayID: gwID, Store: "corp-vault"})
		if !errors.Is(err, refdomain.ErrReferencesNotSupported) {
			t.Fatalf("err = %v, want ErrReferencesNotSupported", err)
		}
	})
	t.Run("an ineligible gateway", func(t *testing.T) {
		tester := NewTester(TesterConfig{Catalog: oneStore{store: vaultStore(), backend: &fakeBackend{}}, Eligibility: domain.EligibilityHybrid, Gateways: gateways{gw("")}})
		_, err := tester.Test(context.Background(), TestInput{GatewayID: gwID, Store: "corp-vault"})
		if !errors.Is(err, refdomain.ErrReferencesNotSupported) {
			t.Fatalf("err = %v, want ErrReferencesNotSupported", err)
		}
	})
}
