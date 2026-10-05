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
	"strings"
	"testing"
)

// TestSaaSOverlaysKeepOutboundGuard loads each SaaS overlay's config.env the way
// its configMapGenerator does and checks the resulting config. TrustGate allows
// private destinations and the ambient Model Armor identity by default for
// single-operator installs, so these overlays are the only thing keeping the
// shared gateways guarded: dropping a line, or renaming a variable in code
// without renaming it here, must fail this test instead of opening the SaaS.
func TestSaaSOverlaysKeepOutboundGuard(t *testing.T) {
	overlays, err := filepath.Glob(filepath.Join("..", "..", "k8s", "overlays", "*", "config.env"))
	if err != nil || len(overlays) == 0 {
		t.Fatalf("no overlay config.env found (err=%v)", err)
	}
	for _, path := range overlays {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			// Start from the code defaults, whatever the test process inherited.
			t.Setenv("OUTBOUND_ALLOW_PRIVATE_NETWORKS", "")
			t.Setenv("PROVIDER_ALLOW_PRIVATE_NETWORKS", "")
			t.Setenv("MODEL_ARMOR_ALLOW_AMBIENT_IDENTITY", "")

			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("open overlay: %v", err)
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if k, v, ok := strings.Cut(line, "="); ok {
					t.Setenv(k, v)
				}
			}
			if err := sc.Err(); err != nil {
				t.Fatalf("read overlay: %v", err)
			}

			if getOutboundConfig().AllowPrivateNetworks {
				t.Error("shared gateway allows tenant-steered outbound URLs to reach private addresses")
			}
			if getModelArmorConfig().AllowAmbientIdentity {
				t.Error("shared gateway allows Model Armor auth through the pod identity")
			}
		})
	}
}
