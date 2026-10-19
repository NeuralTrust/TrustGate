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

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

func TestStoreInstall_UnknownCodeIsAToolError(t *testing.T) {
	tool := storeToolWithInstaller(t, &fakeInstaller{
		installErr: fmt.Errorf("%w: %q", appstore.ErrCatalogEntryNotFound, "nope"),
	})
	raw, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreInstallToolName, json.RawMessage(`{"code":"nope"}`))
	if err != nil {
		t.Fatalf("unknown code must be a tool error, not a Go error: %v", err)
	}
	if !resultIsError(t, raw) {
		t.Fatal("unknown code must set isError")
	}
	if got := decodeText(t, raw); got != "no catalog server with code nope" {
		t.Fatalf("text = %q", got)
	}
}

func TestStoreInstall_SSETransportIsAToolError(t *testing.T) {
	tool := storeToolWithInstaller(t, &fakeInstaller{installErr: appstore.ErrSSEUnsupported})
	raw, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreInstallToolName, json.RawMessage(`{"code":"com.replicate/mcp"}`))
	if err != nil {
		t.Fatalf("SSE install must be a tool error, not a Go error: %v", err)
	}
	if !resultIsError(t, raw) {
		t.Fatal("SSE install must set isError")
	}
	if got := decodeText(t, raw); got != "SSE transport is not supported by the gateway yet" {
		t.Fatalf("text = %q", got)
	}
}

func TestStoreInstall_AdminOnlyInlineConfigIsAToolError(t *testing.T) {
	for _, tc := range []struct {
		field string
		value string
		err   error
	}{
		{
			field: "shop",
			value: "acme.myshopify.com",
			err:   fmt.Errorf("%w: variable %q is set by an admin on the registry", appstore.ErrConfigInvalid, "shop"),
		},
		{
			field: "domain",
			value: "acme.example",
			err:   fmt.Errorf("%w: variable %q must be set by an admin on the registry", appstore.ErrConfigInvalid, "domain"),
		},
	} {
		t.Run(tc.field, func(t *testing.T) {
			tool := storeToolWithInstaller(t, &fakeInstaller{installErr: tc.err})
			raw := callInstallToolError(t, tool, fmt.Sprintf(`{"code":"shopify","config":{%q:%q}}`, tc.field, tc.value))
			text := decodeText(t, raw)
			if !strings.Contains(text, `"`+tc.field+`"`) {
				t.Fatalf("text = %q, want the variable name", text)
			}
			if strings.Contains(string(raw), tc.value) {
				t.Fatalf("result echoed the submitted value %q: %s", tc.value, raw)
			}
		})
	}
}

func TestStoreInstall_InlineSecretIsAToolError(t *testing.T) {
	const secret = "sk-live-secret-value"
	tool := storeToolWithInstaller(t, &fakeInstaller{
		installErr: fmt.Errorf("%w: %q is a secret and must be set through the configure form, not inline", appstore.ErrConfigInvalid, "token"),
	})
	raw := callInstallToolError(t, tool, `{"code":"brightdata","config":{"token":"`+secret+`"}}`)
	text := decodeText(t, raw)
	if !strings.Contains(text, `"token"`) {
		t.Fatalf("text = %q, want the variable name", text)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("result echoed the secret: %s", raw)
	}
}

func TestStoreInstall_UnknownVariableIsAToolError(t *testing.T) {
	const value = "not-a-real-setting"
	tool := storeToolWithInstaller(t, &fakeInstaller{
		installErr: fmt.Errorf("%w: unknown variable %q", appstore.ErrConfigInvalid, "nope"),
	})
	raw := callInstallToolError(t, tool, `{"code":"github","config":{"nope":"`+value+`"}}`)
	text := decodeText(t, raw)
	if !strings.Contains(text, `"nope"`) || !strings.Contains(text, "unknown variable") {
		t.Fatalf("text = %q, want the unknown variable", text)
	}
	if strings.Contains(string(raw), value) {
		t.Fatalf("result echoed the submitted value: %s", raw)
	}
}

func TestStoreInstall_NonUUIDInstanceIsAToolError(t *testing.T) {
	inst := &fakeInstaller{}
	tool := storeToolWithInstaller(t, inst)
	raw := callInstallToolError(t, tool, `{"code":"github","instance":"default"}`)
	if got := decodeText(t, raw); got != "instance must be one of the listed instance ids" {
		t.Fatalf("text = %q", got)
	}
	if strings.Contains(string(raw), "default") {
		t.Fatalf("result echoed the submitted instance id: %s", raw)
	}
	if len(inst.installed) != 0 {
		t.Fatalf("a refused instance must not be recorded, got %v", inst.installed)
	}
}

func TestStoreInstall_UnknownInstanceIsAToolError(t *testing.T) {
	const id = "11111111-1111-1111-1111-111111111111"
	inst := &fakeInstaller{
		installErr: fmt.Errorf("%w: %q is not an instance of %q", appstore.ErrUnknownInstance, id, "github"),
	}
	tool := storeToolWithInstaller(t, inst)
	raw := callInstallToolError(t, tool, `{"code":"github","instance":"`+id+`"}`)
	if got := decodeText(t, raw); got != "instance must be one of the listed instance ids" {
		t.Fatalf("text = %q", got)
	}
	if strings.Contains(string(raw), id) {
		t.Fatalf("result echoed the submitted instance id: %s", raw)
	}
}

func TestStoreInstall_OtherInstallErrorStaysAGoError(t *testing.T) {
	tool := storeToolWithInstaller(t, &fakeInstaller{installErr: errors.New("db down")})
	_, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreInstallToolName, json.RawMessage(`{"code":"github"}`))
	if err == nil || err.Error() != "db down" {
		t.Fatalf("err = %v, want the installer error unchanged", err)
	}
}

func callInstallToolError(t *testing.T, tool StoreTool, arguments string) json.RawMessage {
	t.Helper()
	raw, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreInstallToolName, json.RawMessage(arguments))
	if err != nil {
		t.Fatalf("install refusal must be a tool error, not a Go error (-32603): %v", err)
	}
	if !resultIsError(t, raw) {
		t.Fatal("install refusal must set isError")
	}
	return raw
}

func TestStoreUninstall_NeverInstalledIsIdempotent(t *testing.T) {
	tool := storeToolWithInstaller(t, &fakeInstaller{uninstallErr: appstore.ErrNothingInstalled})
	raw, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreUninstallToolName, json.RawMessage(`{"code":"com.replicate/mcp"}`))
	if err != nil {
		t.Fatalf("uninstall of a code that was never installed must succeed: %v", err)
	}
	if got := decodeText(t, raw); got != "com.replicate/mcp is not installed." {
		t.Fatalf("text = %q", got)
	}
	structured := decodeStructured(t, raw)
	if structured["uninstalled"] != false || structured["was_installed"] != false {
		t.Fatalf("structured = %v, want uninstalled false and was_installed false", structured)
	}
}

func TestStoreUninstall_InstalledReportsWasInstalled(t *testing.T) {
	installer := &fakeInstaller{}
	tool := storeToolWithInstaller(t, installer)
	raw, err := tool.Call(ctxWithPrincipal(), storeRC(), "", StoreUninstallToolName, json.RawMessage(`{"code":"github"}`))
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if got := decodeText(t, raw); got != "Uninstalled github." {
		t.Fatalf("text = %q", got)
	}
	structured := decodeStructured(t, raw)
	if structured["uninstalled"] != true || structured["was_installed"] != true {
		t.Fatalf("structured = %v, want uninstalled true and was_installed true", structured)
	}
	if len(installer.uninstalled) != 1 {
		t.Fatalf("installer calls = %v", installer.uninstalled)
	}
}

func TestStoreSearch_ReportsInstalledCodes(t *testing.T) {
	tool := storeToolWithInstaller(t, &fakeInstaller{
		installedCodes: map[string]struct{}{"gitlab": {}},
	})
	ctx := identity.WithPrincipal(selfServiceCtx(), &identity.Principal{Subject: "ana"})
	raw, err := tool.Call(ctx, storeRC(), "", StoreSearchToolName, json.RawMessage(`{"query":"git"}`))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	got := resultsByCode(t, raw)
	if got["gitlab"]["store_state"] != storeStateInstalled {
		t.Fatalf("gitlab store_state = %v, want installed", got["gitlab"]["store_state"])
	}
	if got["github"]["store_state"] != storeStateAvailable {
		t.Fatalf("github store_state = %v, want available", got["github"]["store_state"])
	}
}

func TestStoreSearch_InstalledLookupFailureStillAnswers(t *testing.T) {
	tool := storeToolWithInstaller(t, &fakeInstaller{installedCodesErr: errors.New("installations unavailable")})
	ctx := identity.WithPrincipal(selfServiceCtx(), &identity.Principal{Subject: "ana"})
	raw, err := tool.Call(ctx, storeRC(), "", StoreSearchToolName, json.RawMessage(`{"query":"git"}`))
	if err != nil {
		t.Fatalf("search must still answer when installed codes cannot be read: %v", err)
	}
	got := resultsByCode(t, raw)
	if got["gitlab"]["store_state"] != storeStateAvailable {
		t.Fatalf("gitlab store_state = %v, want available when the lookup fails", got["gitlab"]["store_state"])
	}
}

func resultIsError(t *testing.T, raw json.RawMessage) bool {
	t.Helper()
	var out struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return out.IsError
}
