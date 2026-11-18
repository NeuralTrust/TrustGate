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

package store_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/gofiber/fiber/v2"
)

type memoryAgentAccess struct {
	rows []*storeaccessdomain.AgentAccess
}

func (m *memoryAgentAccess) ListAgentAccessByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.AgentAccess, error) {
	return m.rows, nil
}

func (m *memoryAgentAccess) ListAgentAccess(context.Context, int, int) ([]*storeaccessdomain.AgentAccess, int, error) {
	return m.rows, len(m.rows), nil
}

func (m *memoryAgentAccess) UpsertAgentAccess(_ context.Context, a *storeaccessdomain.AgentAccess) error {
	_ = m.DeleteAgentAccess(context.Background(), a.GatewayID, a.PrincipalType, a.PrincipalID)
	m.rows = append(m.rows, a)
	return nil
}

func (m *memoryAgentAccess) DeleteAgentAccess(_ context.Context, _ ids.GatewayID, pt storeaccessdomain.PrincipalType, pid string) error {
	kept := m.rows[:0]
	for _, r := range m.rows {
		if r.PrincipalType != pt || r.PrincipalID != pid {
			kept = append(kept, r)
		}
	}
	m.rows = kept
	return nil
}

func (m *memoryAgentAccess) PruneAgentRegistry(context.Context, ids.GatewayID, ids.RegistryID) error {
	return nil
}

type staticRegistries []*registrydomain.Registry

func (s staticRegistries) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return s, len(s), nil
}

func agentAccessApp(t *testing.T, gw ids.GatewayID, registries ...*registrydomain.Registry) (*fiber.App, *memoryAgentAccess) {
	t.Helper()
	repo := &memoryAgentAccess{}
	svc, err := appstore.NewAgentAccessService(repo, staticRegistries(registries), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := storehttp.NewAgentAccessHandler(svc)
	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/store/agent-access", h.List)
	app.Put("/v1/gateways/:gateway_id/store/agent-access", h.Set)
	return app, repo
}

func doAgentAccess(t *testing.T, app *fiber.App, method, url, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

func TestAgentAccessHandler(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	agent := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, Type: registrydomain.TypeA2A}
	mcp := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, Type: registrydomain.TypeMCP}
	app, repo := agentAccessApp(t, gw, agent, mcp)
	url := "/v1/gateways/" + gw.String() + "/store/agent-access"

	status, raw := doAgentAccess(t, app, http.MethodGet, url, "")
	if status != http.StatusOK || string(raw) != `{"rows":[]}` {
		t.Fatalf("empty list: %d %s", status, raw)
	}

	status, raw = doAgentAccess(t, app, http.MethodPut, url, `{"principal_type":"group","principal_id":"eng","mode":"selected","registry_ids":["`+agent.ID.String()+`"]}`)
	if status != http.StatusOK {
		t.Fatalf("put selected: %d %s", status, raw)
	}
	var saved struct {
		PrincipalType string   `json:"principal_type"`
		PrincipalID   string   `json:"principal_id"`
		Mode          string   `json:"mode"`
		RegistryIDs   []string `json:"registry_ids"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil || saved.PrincipalType != "group" || saved.PrincipalID != "eng" ||
		saved.Mode != "selected" || len(saved.RegistryIDs) != 1 || saved.RegistryIDs[0] != agent.ID.String() {
		t.Fatalf("saved row: %s (%v)", raw, err)
	}

	status, raw = doAgentAccess(t, app, http.MethodPut, url, `{"principal_type":"all","principal_id":"","mode":"all"}`)
	if status != http.StatusOK || !strings.Contains(string(raw), `"registry_ids":[]`) {
		t.Fatalf("put all: %d %s", status, raw)
	}

	status, raw = doAgentAccess(t, app, http.MethodGet, url, "")
	var list struct {
		Rows []json.RawMessage `json:"rows"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &list) != nil || len(list.Rows) != 2 {
		t.Fatalf("list: %d %s", status, raw)
	}

	status, raw = doAgentAccess(t, app, http.MethodPut, url, `{"principal_type":"group","principal_id":"eng","mode":""}`)
	if status != http.StatusNoContent || len(repo.rows) != 1 {
		t.Fatalf("delete: %d %s, %d rows left", status, raw, len(repo.rows))
	}

	for name, tc := range map[string]struct {
		body   string
		status int
	}{
		"malformed json":        {`{"principal_type":`, http.StatusBadRequest},
		"registry id not uuid":  {`{"principal_type":"all","mode":"selected","registry_ids":["x"]}`, http.StatusBadRequest},
		"mcp registry":          {`{"principal_type":"all","mode":"selected","registry_ids":["` + mcp.ID.String() + `"]}`, http.StatusUnprocessableEntity},
		"unknown principal":     {`{"principal_type":"team","principal_id":"x","mode":"all"}`, http.StatusUnprocessableEntity},
		"id on the all row":     {`{"principal_type":"all","principal_id":"ana","mode":"all"}`, http.StatusUnprocessableEntity},
		"user without an id":    {`{"principal_type":"user","mode":"none"}`, http.StatusUnprocessableEntity},
		"unknown mode":          {`{"principal_type":"user","principal_id":"ana","mode":"open"}`, http.StatusUnprocessableEntity},
		"selected ids for none": {`{"principal_type":"user","principal_id":"ana","mode":"none","registry_ids":["` + agent.ID.String() + `"]}`, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			if status, raw := doAgentAccess(t, app, http.MethodPut, url, tc.body); status != tc.status {
				t.Fatalf("status %d, want %d: %s", status, tc.status, raw)
			}
		})
	}
}
