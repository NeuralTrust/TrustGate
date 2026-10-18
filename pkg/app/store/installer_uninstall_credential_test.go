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

package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

type recordingVault struct {
	mu        sync.Mutex
	creds     map[string]*vaultdomain.Credential
	calls     []string
	deleteErr error
	findErr   error
}

func credKey(sub, provider string) string { return sub + "\x00" + provider }

func (v *recordingVault) Upsert(context.Context, *vaultdomain.Credential) error { return nil }

func (v *recordingVault) Find(_ context.Context, _ ids.GatewayID, sub, provider string) (*vaultdomain.Credential, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls = append(v.calls, "find")
	if v.findErr != nil {
		return nil, v.findErr
	}
	cred, ok := v.creds[credKey(sub, provider)]
	if !ok {
		return nil, vaultdomain.ErrNotFound
	}
	return cred, nil
}

func (v *recordingVault) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*vaultdomain.Credential, error) {
	return nil, nil
}

func (v *recordingVault) Delete(_ context.Context, _ ids.GatewayID, sub, provider string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls = append(v.calls, "delete")
	if v.deleteErr != nil {
		return v.deleteErr
	}
	key := credKey(sub, provider)
	if _, ok := v.creds[key]; !ok {
		return vaultdomain.ErrNotFound
	}
	delete(v.creds, key)
	return nil
}

type lockingVault struct {
	recordingVault
	provider string
	held     bool
	released bool
	lockErr  error
	lockDL   bool
}

func (v *lockingVault) AcquireRefreshLock(ctx context.Context, _ ids.GatewayID, _, provider string) (func(context.Context) error, error) {
	v.mu.Lock()
	v.provider = provider
	v.held = true
	v.lockErr = ctx.Err()
	_, v.lockDL = ctx.Deadline()
	v.mu.Unlock()
	return func(context.Context) error {
		v.mu.Lock()
		v.held = false
		v.released = true
		v.mu.Unlock()
		return nil
	}, nil
}

type fakeRevoker struct {
	mu       sync.Mutex
	err      error
	calls    int
	tokens   []string
	ctxErr   error
	hasDL    bool
	onRevoke func()
}

func (f *fakeRevoker) Revoke(ctx context.Context, _ ids.GatewayID, _ string, _ *registrydomain.Registry, cred *vaultdomain.Credential) error {
	if f.onRevoke != nil {
		f.onRevoke()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.ctxErr = ctx.Err()
	_, f.hasDL = ctx.Deadline()
	if cred != nil {
		f.tokens = append(f.tokens, cred.AccessToken, cred.RefreshToken)
	}
	return f.err
}

func credentialInstaller(
	t *testing.T,
	regs *fakeRegistries,
	installs installationdomain.Repository,
	vault vaultdomain.Repository,
	revoker CredentialRevoker,
	logger *slog.Logger,
) Installer {
	t.Helper()
	inst, err := NewInstaller(testCatalog(), regs, installs, nil, nil, WithUninstallCredentials(vault, revoker, logger))
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	return inst
}

func installedRow(code string, reg ids.RegistryID) *installationdomain.Installation {
	return &installationdomain.Installation{
		ID:           ids.New[ids.InstallationKind](),
		CatalogCode:  code,
		RegistryID:   reg,
		Status:       installationdomain.StatusInstalled,
		PrincipalSub: "ana",
	}
}

func oauthRegistry(code, name, provider, rawURL string) *registrydomain.Registry {
	reg := forwardedRegistry(code, name, provider)
	reg.MCPTarget.URL = rawURL
	reg.MCPTarget.Origin = registrydomain.MCPOriginStore
	return reg
}

func TestUninstallSolePerUserCredentialDeletesVaultAndRequiresAuthOnReinstall(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	reg.GatewayID = gw
	provider := registrydomain.ForwardedVaultProvider(reg)
	ana, err := vaultdomain.NewCredential(gw, "ana", provider, "ana@corp", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := vaultdomain.NewCredential(gw, "bob", provider, "bob@corp", "bob-access", "bob-refresh", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vault := &recordingVault{creds: map[string]*vaultdomain.Credential{
		credKey("ana", provider): ana,
		credKey("bob", provider): bob,
	}}
	revoker := &fakeRevoker{}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	row := installedRow("github", reg.ID)
	rows := []*installationdomain.Installation{row}
	inst := credentialInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{reg}}, &fakeInstalls{byCode: rows, byPrincipal: rows}, vault, revoker, logger)

	if err := inst.Uninstall(context.Background(), gw, "ana", "github", ""); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := vault.Find(context.Background(), gw, "ana", provider); !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatalf("ana credential = %v, want gone", err)
	}
	if _, err := vault.Find(context.Background(), gw, "bob", provider); err != nil {
		t.Fatalf("another principal's credential must stay: %v", err)
	}
	if revoker.calls != 1 || len(revoker.tokens) != 2 || revoker.tokens[0] != "access-token" || revoker.tokens[1] != "refresh-token" {
		t.Fatalf("revoker calls=%d tokens=%v", revoker.calls, revoker.tokens)
	}
	if !strings.Contains(logs.String(), "mcp_provider_unlinked") || !strings.Contains(logs.String(), "store_uninstall") {
		t.Fatalf("audit log = %s", logs.String())
	}
	if strings.Contains(logs.String(), "access-token") || strings.Contains(logs.String(), "refresh-token") {
		t.Fatalf("audit log leaked a token: %s", logs.String())
	}

	res, err := inst.Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.RequiresAuth {
		t.Fatalf("reinstall = %+v, want requires_auth", res)
	}
	if _, err := vault.Find(context.Background(), gw, "ana", provider); !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatal("reinstall must not find a stored credential")
	}
}

func TestUninstallKeepsSharedVaultKeyUntilTheLastInstall(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	full := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	readOnly := oauthRegistry("github", "GitHub read-only", "github", "https://mcp.github.com/mcp/")
	if registrydomain.ForwardedVaultProvider(full) != registrydomain.ForwardedVaultProvider(readOnly) {
		t.Fatal("fixture registries must share one vault key")
	}
	provider := registrydomain.ForwardedVaultProvider(full)
	cred, err := vaultdomain.NewCredential(gw, "ana", provider, "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vault := &recordingVault{creds: map[string]*vaultdomain.Credential{credKey("ana", provider): cred}}
	revoker := &fakeRevoker{}
	one := installedRow("github", full.ID)
	two := installedRow("github", readOnly.ID)
	rows := []*installationdomain.Installation{one, two}
	inst := credentialInstaller(t,
		&fakeRegistries{items: []*registrydomain.Registry{full, readOnly}},
		&fakeInstalls{byCode: rows, byPrincipal: rows},
		vault, revoker, nil)

	err = inst.Uninstall(context.Background(), gw, "ana", "github", "")
	if !errors.Is(err, ErrAmbiguousInstance) {
		t.Fatalf("two installs without an instance id: %v", err)
	}
	if revoker.calls != 0 || len(vault.calls) != 0 {
		t.Fatalf("ambiguous uninstall touched the credential: revoker=%d vault=%v", revoker.calls, vault.calls)
	}

	if err := inst.Uninstall(context.Background(), gw, "ana", "github", one.ID.String()); err != nil {
		t.Fatalf("uninstall first: %v", err)
	}
	if revoker.calls != 0 {
		t.Fatalf("revoker calls = %d, want 0 while another install shares the key", revoker.calls)
	}
	if _, err := vault.Find(context.Background(), gw, "ana", provider); err != nil {
		t.Fatalf("shared credential must stay after the first uninstall: %v", err)
	}

	if err := inst.Uninstall(context.Background(), gw, "ana", "github", two.ID.String()); err != nil {
		t.Fatalf("uninstall last: %v", err)
	}
	if revoker.calls != 1 {
		t.Fatalf("revoker calls = %d, want 1 on the last install", revoker.calls)
	}
	if _, err := vault.Find(context.Background(), gw, "ana", provider); !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatalf("last uninstall credential = %v, want gone", err)
	}
}

func TestUninstallSharedAccountLeavesTheCredential(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	reg.MCPTarget.Auth.Account = registrydomain.MCPAccountShared
	provider := registrydomain.ForwardedVaultProvider(reg)
	sharedSub := registrydomain.CredentialSubject(reg, "ana")
	cred, err := vaultdomain.NewCredential(gw, sharedSub, provider, "shared", "shared-access", "shared-refresh", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vault := &recordingVault{creds: map[string]*vaultdomain.Credential{credKey(sharedSub, provider): cred}}
	revoker := &fakeRevoker{}
	row := installedRow("github", reg.ID)
	rows := []*installationdomain.Installation{row}
	inst := credentialInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{reg}}, &fakeInstalls{byCode: rows, byPrincipal: rows}, vault, revoker, nil)

	if err := inst.Uninstall(context.Background(), gw, "ana", "github", ""); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if revoker.calls != 0 || len(vault.calls) != 0 {
		t.Fatalf("shared account must not touch the vault: revoker=%d vault=%v", revoker.calls, vault.calls)
	}
	if _, err := vault.Find(context.Background(), gw, sharedSub, provider); err != nil {
		t.Fatalf("shared credential = %v", err)
	}
}

func TestUninstallNonOAuthMakesNoVaultCall(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	for _, auth := range []*registrydomain.MCPAuth{
		{Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer static"},
		{Mode: registrydomain.MCPAuthModeNone},
		nil,
	} {
		reg := shelfRegistry("github")
		reg.Type = registrydomain.TypeMCP
		reg.MCPTarget.Auth = auth
		vault := &recordingVault{creds: map[string]*vaultdomain.Credential{}}
		revoker := &fakeRevoker{}
		row := installedRow("github", reg.ID)
		rows := []*installationdomain.Installation{row}
		inst := credentialInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{reg}}, &fakeInstalls{byCode: rows, byPrincipal: rows}, vault, revoker, nil)
		if err := inst.Uninstall(context.Background(), gw, "ana", "github", ""); err != nil {
			t.Fatalf("auth %+v: %v", auth, err)
		}
		if revoker.calls != 0 || len(vault.calls) != 0 {
			t.Fatalf("auth %+v made a vault call: revoker=%d vault=%v", auth, revoker.calls, vault.calls)
		}
	}
}

func TestUninstallNeverInstalledLeavesTheVaultAlone(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	vault := &recordingVault{creds: map[string]*vaultdomain.Credential{}}
	revoker := &fakeRevoker{}
	installs := &fakeInstalls{}
	inst := credentialInstaller(t, &fakeRegistries{}, installs, vault, revoker, nil)

	if err := inst.Uninstall(context.Background(), gw, "ana", "github", ""); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if installs.deletes != 1 || installs.deleteByID != 0 {
		t.Fatalf("deletes=%d deleteByID=%d", installs.deletes, installs.deleteByID)
	}
	if revoker.calls != 0 || len(vault.calls) != 0 {
		t.Fatalf("never-installed uninstall touched the vault: revoker=%d vault=%v", revoker.calls, vault.calls)
	}
}

func TestUninstallVendorRevocationErrorStillDeletesLocalCredential(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	provider := registrydomain.ForwardedVaultProvider(reg)
	cred, err := vaultdomain.NewCredential(gw, "ana", provider, "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vault := &recordingVault{creds: map[string]*vaultdomain.Credential{credKey("ana", provider): cred}}
	revoker := &fakeRevoker{err: errors.New("vendor down")}
	var logs bytes.Buffer
	row := installedRow("github", reg.ID)
	rows := []*installationdomain.Installation{row}
	inst := credentialInstaller(t,
		&fakeRegistries{items: []*registrydomain.Registry{reg}},
		&fakeInstalls{byCode: rows, byPrincipal: rows},
		vault, revoker, slog.New(slog.NewTextHandler(&logs, nil)))

	if err := inst.Uninstall(context.Background(), gw, "ana", "github", ""); err != nil {
		t.Fatalf("vendor revocation failure must not fail uninstall: %v", err)
	}
	if _, err := vault.Find(context.Background(), gw, "ana", provider); !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatalf("local credential = %v, want gone", err)
	}
	if !strings.Contains(logs.String(), "mcp_token_revocation_failed") || !strings.Contains(logs.String(), "vendor down") {
		t.Fatalf("revocation failure log = %s", logs.String())
	}
	if strings.Contains(logs.String(), "access-token") || strings.Contains(logs.String(), "refresh-token") {
		t.Fatalf("revocation log leaked a token: %s", logs.String())
	}
}

func TestUninstallVaultDeleteErrorKeepsTheInstallation(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	provider := registrydomain.ForwardedVaultProvider(reg)
	cred, err := vaultdomain.NewCredential(gw, "ana", provider, "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vault := &recordingVault{
		creds:     map[string]*vaultdomain.Credential{credKey("ana", provider): cred},
		deleteErr: errors.New("vault unavailable"),
	}
	row := installedRow("github", reg.ID)
	rows := []*installationdomain.Installation{row}
	installs := &fakeInstalls{byCode: rows, byPrincipal: rows}
	revoker := &fakeRevoker{}
	inst := credentialInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{reg}}, installs, vault, revoker, nil)

	err = inst.Uninstall(context.Background(), gw, "ana", "github", "")
	if err == nil || !strings.Contains(err.Error(), "vault unavailable") {
		t.Fatalf("Uninstall error = %v, want the vault delete error", err)
	}
	if installs.deleteByID != 0 || row.Status != installationdomain.StatusInstalled {
		t.Fatalf("installation must stay installed, status=%s deleteByID=%d", row.Status, installs.deleteByID)
	}
	if _, err := vault.Find(context.Background(), gw, "ana", provider); err != nil {
		t.Fatalf("credential must stay when delete fails: %v", err)
	}
	if revoker.calls != 0 {
		t.Fatalf("revoker calls = %d, want 0 when the local delete fails", revoker.calls)
	}
}

func TestUninstallCredentialAlreadyGoneIsSuccess(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	provider := registrydomain.ForwardedVaultProvider(reg)
	vault := &recordingVault{creds: map[string]*vaultdomain.Credential{}}
	revoker := &fakeRevoker{}
	var logs bytes.Buffer
	row := installedRow("github", reg.ID)
	rows := []*installationdomain.Installation{row}
	installs := &fakeInstalls{byCode: rows, byPrincipal: rows}
	inst := credentialInstaller(t,
		&fakeRegistries{items: []*registrydomain.Registry{reg}},
		installs, vault, revoker, slog.New(slog.NewTextHandler(&logs, nil)))

	if err := inst.Uninstall(context.Background(), gw, "ana", "github", ""); err != nil {
		t.Fatalf("missing credential must not fail uninstall: %v", err)
	}
	if revoker.calls != 0 {
		t.Fatalf("revoker calls = %d, want 0", revoker.calls)
	}
	if installs.deleteByID != 1 {
		t.Fatalf("deleteByID = %d", installs.deleteByID)
	}
	if strings.Contains(logs.String(), "mcp_provider_unlinked") {
		t.Fatalf("a missing credential is not an unlink: %s", logs.String())
	}
	if _, err := vault.Find(context.Background(), gw, "ana", provider); !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatalf("credential = %v", err)
	}
}

func TestUninstallRevocationIgnoresCallerCancel(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	provider := registrydomain.ForwardedVaultProvider(reg)
	cred, err := vaultdomain.NewCredential(gw, "ana", provider, "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vault := &lockingVault{recordingVault: recordingVault{creds: map[string]*vaultdomain.Credential{credKey("ana", provider): cred}}}
	revoker := &fakeRevoker{}
	row := installedRow("github", reg.ID)
	rows := []*installationdomain.Installation{row}
	inst := credentialInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{reg}}, &fakeInstalls{byCode: rows, byPrincipal: rows}, vault, revoker, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := inst.Uninstall(ctx, gw, "ana", "github", ""); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if vault.lockErr != nil || !vault.lockDL {
		t.Fatalf("lock context err=%v deadline=%v", vault.lockErr, vault.lockDL)
	}
	if revoker.ctxErr != nil {
		t.Fatalf("revocation context was cancelled with the caller: %v", revoker.ctxErr)
	}
	if !revoker.hasDL {
		t.Fatal("revocation context has no deadline")
	}
}

func TestUninstallLocksThePerUserCredential(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	provider := registrydomain.ForwardedVaultProvider(reg)
	cred, err := vaultdomain.NewCredential(gw, "ana", provider, "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vault := &lockingVault{recordingVault: recordingVault{creds: map[string]*vaultdomain.Credential{credKey("ana", provider): cred}}}
	revoker := &fakeRevoker{onRevoke: func() {
		vault.mu.Lock()
		held := vault.held
		vault.mu.Unlock()
		if held {
			t.Errorf("vendor revoke ran while the credential lock was held")
		}
	}}
	row := installedRow("github", reg.ID)
	rows := []*installationdomain.Installation{row}
	inst := credentialInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{reg}}, &fakeInstalls{byCode: rows, byPrincipal: rows}, vault, revoker, nil)

	if err := inst.Uninstall(context.Background(), gw, "ana", "github", ""); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if vault.provider != provider || !vault.released || vault.held {
		t.Fatalf("lock provider=%q released=%v held=%v", vault.provider, vault.released, vault.held)
	}
	if revoker.calls != 1 {
		t.Fatalf("revoker calls = %d, want 1 after the lock is released", revoker.calls)
	}
}

func TestUninstallKeepsCredentialUsedByAdminRegistry(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	storeReg := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	admin := oauthRegistry("github", "GitHub admin", "github", "https://mcp.github.com/mcp")
	admin.MCPTarget.Origin = ""
	if registrydomain.ForwardedVaultProvider(storeReg) != registrydomain.ForwardedVaultProvider(admin) {
		t.Fatal("admin registry must share the store install's vault key")
	}
	provider := registrydomain.ForwardedVaultProvider(storeReg)
	cred, err := vaultdomain.NewCredential(gw, "ana", provider, "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vault := &recordingVault{creds: map[string]*vaultdomain.Credential{credKey("ana", provider): cred}}
	revoker := &fakeRevoker{}
	row := installedRow("github", storeReg.ID)
	rows := []*installationdomain.Installation{row}
	inst := credentialInstaller(t,
		&fakeRegistries{items: []*registrydomain.Registry{storeReg, admin}},
		&fakeInstalls{byCode: rows, byPrincipal: rows},
		vault, revoker, nil)

	if err := inst.Uninstall(context.Background(), gw, "ana", "github", ""); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if revoker.calls != 0 {
		t.Fatalf("revoker calls = %d, want 0 while an admin registry uses the key", revoker.calls)
	}
	if _, err := vault.Find(context.Background(), gw, "ana", provider); err != nil {
		t.Fatalf("credential an admin registry still uses = %v", err)
	}

	t.Run("shared admin account is a different key", func(t *testing.T) {
		sharedAdmin := oauthRegistry("github", "GitHub shared", "github", "https://mcp.github.com/mcp")
		sharedAdmin.MCPTarget.Origin = ""
		sharedAdmin.MCPTarget.Auth.Account = registrydomain.MCPAccountShared
		cred, err := vaultdomain.NewCredential(gw, "ana", provider, "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		vault := &recordingVault{creds: map[string]*vaultdomain.Credential{credKey("ana", provider): cred}}
		row := installedRow("github", storeReg.ID)
		rows := []*installationdomain.Installation{row}
		inst := credentialInstaller(t,
			&fakeRegistries{items: []*registrydomain.Registry{storeReg, sharedAdmin}},
			&fakeInstalls{byCode: rows, byPrincipal: rows},
			vault, &fakeRevoker{}, nil)
		if err := inst.Uninstall(context.Background(), gw, "ana", "github", ""); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if _, err := vault.Find(context.Background(), gw, "ana", provider); !errors.Is(err, vaultdomain.ErrNotFound) {
			t.Fatalf("per-user credential = %v, want gone", err)
		}
	})
}

type concurrentInstalls struct {
	*fakeInstalls
	mu      sync.Mutex
	entered int
	gate    chan struct{}
}

func (c *concurrentInstalls) FindByID(_ context.Context, _ ids.GatewayID, _ string, id ids.InstallationID) (*installationdomain.Installation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, in := range c.byPrincipal {
		if in != nil && in.ID == id {
			cp := *in
			return &cp, nil
		}
	}
	return nil, installationdomain.ErrNotFound
}

func (c *concurrentInstalls) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	c.mu.Lock()
	c.entered++
	n := c.entered
	if n == 2 {
		close(c.gate)
	}
	c.mu.Unlock()
	if n <= 2 {
		<-c.gate
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*installationdomain.Installation, 0, len(c.byPrincipal))
	for _, in := range c.byPrincipal {
		if in == nil {
			continue
		}
		cp := *in
		out = append(out, &cp)
	}
	return out, nil
}

func (c *concurrentInstalls) DeleteByID(_ context.Context, _ ids.GatewayID, _ string, id ids.InstallationID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteByID++
	for _, in := range c.byPrincipal {
		if in != nil && in.ID == id {
			in.Status = installationdomain.StatusRevoked
		}
	}
	return nil
}

func TestConcurrentUninstallOfSharedCredentialLeavesNothing(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	full := oauthRegistry("github", "GitHub", "github", "https://mcp.github.com/mcp")
	readOnly := oauthRegistry("github", "GitHub read-only", "github", "https://mcp.github.com/mcp/")
	if registrydomain.ForwardedVaultProvider(full) != registrydomain.ForwardedVaultProvider(readOnly) {
		t.Fatal("fixture registries must share one vault key")
	}
	provider := registrydomain.ForwardedVaultProvider(full)
	cred, err := vaultdomain.NewCredential(gw, "ana", provider, "", "access-token", "refresh-token", nil, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vault := &recordingVault{creds: map[string]*vaultdomain.Credential{credKey("ana", provider): cred}}
	one := installedRow("github", full.ID)
	two := installedRow("github", readOnly.ID)
	rows := []*installationdomain.Installation{one, two}
	installs := &concurrentInstalls{
		fakeInstalls: &fakeInstalls{byCode: rows, byPrincipal: rows},
		gate:         make(chan struct{}),
	}
	inst := credentialInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{full, readOnly}}, installs, vault, &fakeRevoker{}, nil)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, row := range rows {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			errs <- inst.Uninstall(context.Background(), gw, "ana", "github", id)
		}(row.ID.String())
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
	}
	if _, err := vault.Find(context.Background(), gw, "ana", provider); !errors.Is(err, vaultdomain.ErrNotFound) {
		t.Fatalf("concurrent uninstall left the credential: %v", err)
	}
	if installs.deleteByID != 2 {
		t.Fatalf("deleteByID = %d, want both installs removed", installs.deleteByID)
	}
}
