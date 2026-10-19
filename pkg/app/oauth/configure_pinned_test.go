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

package oauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// snowflakeAdminRow is a shared admin instance whose URL already names the
// account, leaving only the database to the user.
func snowflakeAdminRow() *registrydomain.Registry {
	r := shelf("snowflake")
	r.MCPTarget.URL = "https://acme.snowflakecomputing.com/mcp?database={database}"
	return r
}

func variableNames(page *oauth.ConfigurePage) []string {
	out := make([]string, 0, len(page.Variables))
	for _, v := range page.Variables {
		out = append(out, v.Name)
	}
	return out
}

func TestConfigure_PageOmitsAVariableTheAdminRowPins(t *testing.T) {
	f := configureFixture(t, true, snowflakeAdminRow())
	page, err := f.svc.Page(context.Background(), f.ticket(t, "snowflake", ""))
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if got := variableNames(page); len(got) != 0 {
		t.Fatalf("a non-secret variable is not collected on the form, got %v", got)
	}
}

func TestConfigure_PageWithoutAnAdminURLAsksForEveryVariable(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake"))
	page, err := f.svc.Page(context.Background(), f.ticket(t, "snowflake", ""))
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if got := variableNames(page); len(got) != 0 {
		t.Fatalf("a non-secret variable is not collected on the form, got %v", got)
	}
}

func TestConfigure_SubmitIgnoresAPinnedValue(t *testing.T) {
	f := configureFixture(t, true, snowflakeAdminRow())
	id := f.ticket(t, "snowflake", "")

	_, err := f.svc.Submit(context.Background(), id, map[string]string{
		"account_url": "other.snowflakecomputing.com",
		"database":    "ANALYTICS",
	})
	if err == nil || !errors.Is(err, oauth.ErrConfigureInvalid) || !strings.Contains(err.Error(), "is set by an admin") {
		t.Fatalf("registry variables must be refused, got %v", err)
	}
	if rows := f.rows(t, "snowflake"); len(rows) != 0 {
		t.Fatalf("nothing may be stored, got %+v", rows)
	}
}

func kibanaRow(url string, at time.Time, enabled bool) *registrydomain.Registry {
	r := shelf("kibana")
	r.CreatedAt = at
	r.Enabled = enabled
	r.MCPTarget.URL = url
	return r
}

func hasVariable(page *oauth.ConfigurePage, name string) bool {
	for _, v := range page.Variables {
		if v.Name == name {
			return true
		}
	}
	return false
}

// The oldest row is disabled and pins host. The installer binds the enabled
// row, whose URL still templates host. The form must ask for it: hiding it
// makes every submit fail incomplete, because the install still needs it.
func TestConfigure_DisabledOldestDoesNotPin(t *testing.T) {
	disabled := kibanaRow("https://pinned.kb.example.com/s/{space}/mcp", time.Unix(1, 0), false)
	enabled := kibanaRow("https://{host}/s/{space}/mcp", time.Unix(2, 0), true)
	f := configureFixture(t, true, disabled, enabled)
	id := f.ticket(t, "kibana", "")

	page, err := f.svc.Page(context.Background(), id)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if hasVariable(page, "host") || hasVariable(page, "space") {
		t.Fatalf("non-secret variables are not collected, got %v", variableNames(page))
	}
	if _, err := f.svc.Submit(context.Background(), id, map[string]string{
		"host":  "kb.example.com",
		"space": "default",
	}); err == nil || !strings.Contains(err.Error(), "is set by an admin") {
		t.Fatalf("registry variables must be refused, got %v", err)
	}
	if rows := f.rows(t, "kibana"); len(rows) != 0 {
		t.Fatalf("nothing may be stored, got %+v", rows)
	}
	_ = enabled
}

// Under Selected the oldest instance is not the one the grant names. Pins
// follow the granted instance, which still templates host.
func TestConfigure_SelectedGrantDoesNotPinTheUngrantedInstance(t *testing.T) {
	oldest := kibanaRow("https://pinned.kb.example.com/s/{space}/mcp", time.Unix(1, 0), true)
	granted := kibanaRow("https://{host}/s/{space}/mcp", time.Unix(2, 0), true)
	g, err := storeaccessdomain.New(ids.New[ids.GatewayKind](), "kibana", granted.ID, nil, []string{"ana"})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	f := configureFixtureGranted(t, false, []*storeaccessdomain.Grant{g}, oldest, granted)
	id := f.ticket(t, "kibana", "")

	page, err := f.svc.Page(context.Background(), id)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if hasVariable(page, "host") || hasVariable(page, "space") {
		t.Fatalf("non-secret variables are not collected, got %v", variableNames(page))
	}
	if _, err := f.svc.Submit(context.Background(), id, map[string]string{
		"host": "kb.example.com",
	}); err == nil || !strings.Contains(err.Error(), "is set by an admin") {
		t.Fatalf("registry variables must be refused, got %v", err)
	}
	_ = granted
}

// Two usable instances: the install cannot choose, so the form pins nothing.
func TestConfigure_AmbiguousInstallPinsNothing(t *testing.T) {
	oldest := kibanaRow("https://pinned.kb.example.com/s/{space}/mcp", time.Unix(1, 0), true)
	other := kibanaRow("https://{host}/s/{space}/mcp", time.Unix(2, 0), true)
	f := configureFixture(t, true, oldest, other)

	page, err := f.svc.Page(context.Background(), f.ticket(t, "kibana", ""))
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if hasVariable(page, "host") || hasVariable(page, "space") {
		t.Fatalf("non-secret variables are not collected, got %v", variableNames(page))
	}
}

func TestConfigure_SubmitStillRejectsAnUndeclaredVariable(t *testing.T) {
	f := configureFixture(t, true, snowflakeAdminRow())
	id := f.ticket(t, "snowflake", "")

	_, err := f.svc.Submit(context.Background(), id, map[string]string{
		"database": "ANALYTICS",
		"bogus":    "x",
	})
	if !errors.Is(err, oauth.ErrConfigureInvalid) {
		t.Fatalf("undeclared variable must be refused, got %v", err)
	}
}
