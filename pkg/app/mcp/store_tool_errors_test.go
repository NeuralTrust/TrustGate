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
