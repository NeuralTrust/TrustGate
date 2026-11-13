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
	"context"
	"fmt"
	"io"
	"time"

	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/container/modules"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// commandSecretRefsScan is the one-off pre-deploy scan: it lists stored
// credential values that look like secret references and exits.
const commandSecretRefsScan = "secret-refs-scan"

// Exit codes of secret-refs-scan. A Job or script tells "found some" apart
// from "could not scan".
const (
	scanExitClean  = 0
	scanExitFailed = 1
	scanExitFound  = 3
)

const scanTimeout = 10 * time.Minute

// runSecretRefsScan reads Postgres through the admin's repositories,
// so encrypted credentials are read decrypted, without running migrations
// or starting any server. It prints gateway, entity, field and kind, never
// a value.
func runSecretRefsScan(stdout, stderr io.Writer) int {
	c, err := container.New(modules.All(serverAdmin, false)...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secret-refs-scan: %v\n", err)
		return scanExitFailed
	}
	var findings []appsecretstore.Finding
	err = c.Invoke(func(repo registrydomain.Repository, gateways gatewaydomain.Repository, entities modules.SecretScanListers) error {
		ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
		defer cancel()
		findings, err = appsecretstore.ScanReferences(ctx, appsecretstore.ScanSources{
			Registries: repo, Gateways: gateways, Entities: entities.Listers(),
		})
		return err
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secret-refs-scan: %v\n", err)
		return scanExitFailed
	}
	return reportFindings(stdout, stderr, findings)
}

// reportFindings prints every finding but fails only on whole references:
// the runtime blanks those, while an embedded one is still sent as before.
func reportFindings(stdout, stderr io.Writer, findings []appsecretstore.Finding) int {
	if len(findings) == 0 {
		_, _ = fmt.Fprintln(stderr, "secret-refs-scan: no stored credential value looks like a secret reference")
		return scanExitClean
	}
	references := 0
	for _, f := range findings {
		if f.Kind == appsecretstore.FindingReference {
			references++
		}
	}
	_, _ = fmt.Fprintln(stdout, "gateway_id\tentity\tid\tname\tfield\tkind")
	for _, f := range findings {
		_, _ = fmt.Fprintf(stdout, "%s\t%s\t%s\t%q\t%s\t%s\n", f.GatewayID, f.Entity, f.ID, f.Name, f.Field, f.Kind)
	}
	_, _ = fmt.Fprintf(stderr, "secret-refs-scan: %d stored credential values are secret references, %d more embed one in a longer value\n",
		references, len(findings)-references)
	if references == 0 {
		return scanExitClean
	}
	return scanExitFound
}
