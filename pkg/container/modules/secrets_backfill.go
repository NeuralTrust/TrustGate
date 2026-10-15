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

package modules

import (
	"context"
	"log/slog"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	authrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/auth"
	registryrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	"go.uber.org/dig"
)

const secretsBackfillTimeout = 10 * time.Minute

// SecretsBackfillParams is what the stored-secrets backfill needs.
type SecretsBackfillParams struct {
	dig.In
	Ctx        context.Context
	Config     *config.Config
	Logger     *slog.Logger
	Registries *registryrepo.Repository
	Auths      *authrepo.Repository
	Catalog    appcatalog.MCPServerCatalog
}

// StartSecretsBackfill encrypts, in the background, credentials stored before
// field encryption existed. Control-plane planes call it on every boot; it does
// nothing unless STORED_SECRETS_ENCRYPTION_ENABLED is on, and it only writes
// rows that still need it, so an interrupted run resumes on the next boot. The
// returned stop cancels the pass and waits for it to return; call it before
// the database pool closes.
func StartSecretsBackfill(p SecretsBackfillParams) (stop func()) {
	if !p.Config.Server.StoredSecretsEncryptionEnabled {
		return func() {}
	}
	ctx, cancel := context.WithTimeout(p.Ctx, secretsBackfillTimeout)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := appregistry.BackfillStoredSecrets(ctx, p.Registries, p.Auths, p.Catalog, p.Logger); err != nil {
			p.Logger.Warn("stored secrets backfill did not finish; it resumes on the next boot",
				slog.String("error", err.Error()))
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
