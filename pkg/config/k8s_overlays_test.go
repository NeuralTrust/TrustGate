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

package config

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSharedGatewayOverlaysKeepOutboundGuardOn pins the deployed shared
// multi-tenant gateways to PROVIDER_ALLOW_PRIVATE_NETWORKS=false. The code
// default is true, so dropping the line from an overlay silently disables the
// SSRF guard in production.
func TestSharedGatewayOverlaysKeepOutboundGuardOn(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..")

	for _, overlay := range []string{"dev", "prod", "prod-us"} {
		t.Run(overlay, func(t *testing.T) {
			path := filepath.Join(repoRoot, "k8s", "overlays", overlay, "config.env")
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("open %s: %v", path, err)
			}
			defer func() { _ = f.Close() }()

			var got string
			found := false
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if v, ok := strings.CutPrefix(line, "PROVIDER_ALLOW_PRIVATE_NETWORKS="); ok {
					got, found = strings.TrimSpace(v), true
				}
			}
			if err := sc.Err(); err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if !found || got != "false" {
				t.Fatalf("%s must set PROVIDER_ALLOW_PRIVATE_NETWORKS=false (found=%v value=%q)", path, found, got)
			}
		})
	}
}
