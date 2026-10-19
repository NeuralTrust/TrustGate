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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
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
	if got := variableNames(page); len(got) != 1 || got[0] != "database" {
		t.Fatalf("form must ask only for the unpinned variable, got %v", got)
	}
}

func TestConfigure_PageWithoutAnAdminURLAsksForEveryVariable(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake"))
	page, err := f.svc.Page(context.Background(), f.ticket(t, "snowflake", ""))
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if got := variableNames(page); len(got) != 2 {
		t.Fatalf("form must ask for every declared variable, got %v", got)
	}
}

func TestConfigure_SubmitIgnoresAPinnedValue(t *testing.T) {
	f := configureFixture(t, true, snowflakeAdminRow())
	id := f.ticket(t, "snowflake", "")

	page, err := f.svc.Submit(context.Background(), id, map[string]string{
		"account_url": "other.snowflakecomputing.com",
		"database":    "ANALYTICS",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !page.Saved {
		t.Fatalf("submit must report saved, got %+v", page)
	}
	rows := f.rows(t, "snowflake")
	if len(rows) != 1 {
		t.Fatalf("expected one installation, got %d", len(rows))
	}
	if _, stored := rows[0].Config["account_url"]; stored {
		t.Fatalf("pinned value must not be stored: %+v", rows[0].Config)
	}
	if rows[0].Config["database"] != "ANALYTICS" {
		t.Fatalf("unpinned value must be stored: %+v", rows[0].Config)
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
