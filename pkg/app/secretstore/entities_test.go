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

package secretstore

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type authPages struct {
	gw  ids.GatewayID
	all []*auth.Auth
}

func (p authPages) List(_ context.Context, f auth.ListFilter) ([]*auth.Auth, int, error) {
	if f.GatewayID != p.gw || f.Enabled != nil {
		panic("the lister must read every auth of the gateway, enabled or not")
	}
	start := (f.Page.Number - 1) * f.Page.Size
	if start >= len(p.all) {
		return nil, len(p.all), nil
	}
	return p.all[start:min(start+f.Page.Size, len(p.all))], len(p.all), nil
}

func TestAuthListerReadsEveryPage(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	pages := authPages{gw: gw}
	for i := range entitiesPageSize + 2 {
		a := &auth.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Name: "plain"}
		if i == entitiesPageSize+1 {
			a.Name = "okta"
			a.Config.OAuth2 = &auth.OAuth2Config{ClientSecret: "secret://vault/idp#secret"}
		}
		pages.all = append(pages.all, a)
	}
	got, err := AuthLister(pages)(context.Background(), gw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != entitiesPageSize+2 {
		t.Fatalf("auths read = %d, want every page", len(got))
	}
	last := got[len(got)-1]
	if last.Name != "okta" || len(last.Uses) != 1 || last.Uses[0].Raw != "secret://vault/idp#secret" {
		t.Fatalf("last = %+v", last)
	}
}

type enabledAuths struct{ all []*auth.Auth }

func (e enabledAuths) ListEnabledByGatewayAndType(_ context.Context, _ ids.GatewayID, t auth.Type) ([]*auth.Auth, error) {
	if t != auth.TypeOAuth2 {
		panic("only OAuth 2.0 auths hold identity provider secrets")
	}
	return e.all, nil
}

func TestEnabledAuthListerReadsWhatAServingPlaneResolves(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	a := &auth.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Name: "okta", Config: auth.Config{OAuth2: &auth.OAuth2Config{
		TokenURL: "https://idp.example/token", ClientSecret: "secret://vault/idp#secret",
	}}}
	got, err := EnabledAuthLister(enabledAuths{all: []*auth.Auth{a}})(context.Background(), gw)
	if err != nil || len(got) != 1 || len(got[0].Uses) != 1 || got[0].Name != "okta" {
		t.Fatalf("got %+v, %v", got, err)
	}
}
