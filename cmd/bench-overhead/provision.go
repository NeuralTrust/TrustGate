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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
)

type adminClient struct {
	base  string
	token string
	http  *http.Client
}

func (a *adminClient) post(path string, payload any, wantStatus int) (map[string]any, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(http.MethodPost, a.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		return nil, fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, raw)
	}
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("POST %s: decode: %w", path, err)
		}
	}
	return out, nil
}

func stringField(m map[string]any, key string) (string, error) {
	v, _ := m[key].(string)
	if v == "" {
		return "", fmt.Errorf("response missing %q: %v", key, m)
	}
	return v, nil
}

func runProvision(args []string) error {
	fs := flag.NewFlagSet("provision", flag.ExitOnError)
	adminURL := fs.String("admin-url", "http://localhost:8080", "admin plane base URL")
	upstream := fs.String("upstream", "http://127.0.0.1:9999/v1", "base_url the registry forwards to")
	tenant := fs.String("tenant", "bench-tenant", "tenant id stamped on the gateway")
	out := fs.String("out", "", "write the provisioned target as KEY=VALUE lines to this file (default stdout)")
	_ = fs.Parse(args)

	secret := os.Getenv("SERVER_SECRET_KEY")
	if secret == "" {
		return errors.New("SERVER_SECRET_KEY must be set to mint the admin token")
	}
	token, err := jwt.NewJwtManager(&config.ServerConfig{SecretKey: secret}).CreateToken()
	if err != nil {
		return fmt.Errorf("mint admin token: %w", err)
	}
	admin := &adminClient{base: *adminURL, token: token, http: &http.Client{Timeout: 30 * time.Second}}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	gw, err := admin.post("/v1/gateways", map[string]any{
		"name":      "bench-" + suffix,
		"tenant_id": *tenant,
		"entitlements": map[string]any{
			"tier":            "enterprise",
			"burst_per_min":   1_000_000_000,
			"quota_per_month": 0,
			"max_instances":   1000,
		},
	}, http.StatusCreated)
	if err != nil {
		return err
	}
	gatewayID, err := stringField(gw, "id")
	if err != nil {
		return err
	}
	gatewaySlug, err := stringField(gw, "slug")
	if err != nil {
		return err
	}
	var proxyHost string
	if hosts, ok := gw["hosts"].(map[string]any); ok {
		proxyHost, _ = hosts["proxy"].(string)
	}

	reg, err := admin.post("/v1/gateways/"+gatewayID+"/registries", map[string]any{
		"name":             "bench-upstream-" + suffix,
		"provider":         "openai",
		"weight":           1,
		"provider_options": map[string]any{"base_url": *upstream},
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "sk-bench"},
		},
	}, http.StatusCreated)
	if err != nil {
		return err
	}
	registryID, err := stringField(reg, "id")
	if err != nil {
		return err
	}

	cons, err := admin.post("/v1/gateways/"+gatewayID+"/consumers", map[string]any{
		"name":       "bench-consumer-" + suffix,
		"registries": []map[string]any{{"id": registryID}},
	}, http.StatusCreated)
	if err != nil {
		return err
	}
	consumerID, err := stringField(cons, "id")
	if err != nil {
		return err
	}
	consumerSlug, err := stringField(cons, "slug")
	if err != nil {
		return err
	}

	auth, err := admin.post("/v1/gateways/"+gatewayID+"/auths", map[string]any{
		"name":    "bench-key-" + suffix,
		"type":    "api_key",
		"enabled": true,
	}, http.StatusCreated)
	if err != nil {
		return err
	}
	authID, err := stringField(auth, "id")
	if err != nil {
		return err
	}
	apiKey, err := stringField(auth, "api_key")
	if err != nil {
		return err
	}
	if _, err := admin.post("/v1/gateways/"+gatewayID+"/consumers/"+consumerID+"/auths/"+authID, nil, http.StatusNoContent); err != nil {
		return err
	}

	lines := fmt.Sprintf("GATEWAY_ID=%s\nGATEWAY_SLUG=%s\nGATEWAY_HOST=%s\nCONSUMER_PATH=/%s/v1/chat/completions\nAPI_KEY=%s\n",
		gatewayID, gatewaySlug, proxyHost, consumerSlug, apiKey)
	if *out == "" {
		_, err = io.WriteString(os.Stdout, lines)
		return err
	}
	return os.WriteFile(*out, []byte(lines), 0o600)
}
