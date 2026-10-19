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
	_ "embed"
	"fmt"
	"sync"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

//go:embed catalog_previous_seed.json
var previousSeedJSON []byte

// ambiguousCatalogCodes changed in the #1102 seed, but an exact URL match
// cannot tell a self-hosted install from the old catalog value. JumpCloud,
// Langfuse, New Relic, Paddle, and Workato keep a concrete host an admin
// stores by filling the new template (the connect panel drops the template
// and the url_variables). Cube's old URL is itself the template
// https://{cube_host}/api/mcp, so a self-hosted install must never be pointed
// at cubecloud.dev. None of these codes are in the previous table.
var ambiguousCatalogCodes = []string{
	"com.jumpcloud/genai",
	"com.langfuse/mcp",
	"com.newrelic/mcp",
	"com.paddle/mcp",
	"com.workato/developer-api",
	"dev.cube/mcp",
}

var (
	previousOnce    sync.Once
	previousByCode  map[string]string
	previousEntries map[string]catalogdomain.MCPServer
	previousLoadErr error
)

func loadPreviousCatalog() {
	previousOnce.Do(func() {
		servers, err := appcatalog.ParseCuratedMCPServers(previousSeedJSON)
		if err != nil {
			previousLoadErr = fmt.Errorf("store: parse previous catalog seed: %w", err)
			return
		}
		entries := make(map[string]catalogdomain.MCPServer, len(servers))
		prints := make(map[string]string, len(servers))
		for _, server := range servers {
			shape, err := storedCatalogShape(server)
			if err != nil {
				previousLoadErr = fmt.Errorf("store: previous catalog shape %q: %w", server.Code, err)
				return
			}
			fp, err := catalogFingerprint(shape)
			if err != nil {
				previousLoadErr = fmt.Errorf("store: previous catalog fingerprint %q: %w", server.Code, err)
				return
			}
			if _, dup := prints[server.Code]; dup {
				previousLoadErr = fmt.Errorf("store: duplicate previous catalog code %q", server.Code)
				return
			}
			entries[server.Code] = server
			prints[server.Code] = fp
		}
		for _, code := range ambiguousCatalogCodes {
			if _, ok := prints[code]; ok {
				previousLoadErr = fmt.Errorf("store: ambiguous catalog code %q is in the previous table", code)
				return
			}
		}
		previousEntries = entries
		previousByCode = prints
	})
}

func previousFingerprint(code string) (string, bool, error) {
	loadPreviousCatalog()
	if previousLoadErr != nil {
		return "", false, previousLoadErr
	}
	fp, ok := previousByCode[code]
	return fp, ok, nil
}

func previousServer(code string) (catalogdomain.MCPServer, bool, error) {
	loadPreviousCatalog()
	if previousLoadErr != nil {
		return catalogdomain.MCPServer{}, false, previousLoadErr
	}
	server, ok := previousEntries[code]
	return server, ok, nil
}
