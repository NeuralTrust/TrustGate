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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/adapters"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"gopkg.in/yaml.v3"
)

type k8sDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Default struct {
			Config struct {
				HTTPHealthCheck struct {
					RequestPath string `yaml:"requestPath"`
				} `yaml:"httpHealthCheck"`
			} `yaml:"config"`
		} `yaml:"default"`
		TargetRef struct {
			Name string `yaml:"name"`
		} `yaml:"targetRef"`
		Template struct {
			Spec struct {
				Containers []struct {
					ReadinessProbe struct {
						HTTPGet struct {
							Path string `yaml:"path"`
						} `yaml:"httpGet"`
					} `yaml:"readinessProbe"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func k8sDocs(t *testing.T, root string) []k8sDoc {
	t.Helper()
	var docs []k8sDoc
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var doc k8sDoc
			if err := dec.Decode(&doc); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return fmt.Errorf("%s: %w", path, err)
			}
			docs = append(docs, doc)
		}
	})
	if err != nil {
		t.Fatalf("read k8s manifests: %v", err)
	}
	return docs
}

// The load balancer only stops sending traffic to a pod when its own health
// check fails, independently of the kubelet readiness probe. Data-plane pods
// serve from a config snapshot, so both must agree on the readiness endpoint.
func TestDataPlaneLoadBalancerHealthChecksUseReadiness(t *testing.T) {
	docs := k8sDocs(t, filepath.Join("..", "..", "..", "k8s"))

	readiness := map[string]string{}
	for _, d := range k8sDocs(t, filepath.Join("..", "..", "..", "k8s", "base", "deployment")) {
		if d.Kind == "Deployment" && len(d.Spec.Template.Spec.Containers) > 0 {
			readiness[d.Metadata.Name] = d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Path
		}
	}
	for _, plane := range []string{"agentgateway-proxy", "agentgateway-mcp"} {
		if readiness[plane] != "/readyz" {
			t.Fatalf("%s readinessProbe path = %q, want /readyz", plane, readiness[plane])
		}
	}

	checked := 0
	for _, d := range docs {
		if d.Kind != "HealthCheckPolicy" {
			continue
		}
		target := d.Spec.TargetRef.Name
		if !strings.HasPrefix(target, "agentgateway-proxy") && !strings.HasPrefix(target, "agentgateway-mcp") {
			continue
		}
		checked++
		if got := d.Spec.Default.Config.HTTPHealthCheck.RequestPath; got != "/readyz" {
			t.Errorf("HealthCheckPolicy %s (target %s) requestPath = %q, want /readyz", d.Metadata.Name, target, got)
		}
	}
	if checked == 0 {
		t.Fatal("no data-plane HealthCheckPolicy found")
	}
}

// A data-plane pod with no config snapshot fails readiness and cannot register
// OAuth clients; publishing a snapshot fixes both at once. This is the state a
// new pod is in while it cannot reach the control plane.
func TestDataPlaneRegistrationFollowsSnapshotReadiness(t *testing.T) {
	t.Parallel()
	store := configsync.NewMemoryStore[*readmodel.Snapshot]()
	defaultIdP := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{Issuer: "https://idp.example.com", ClientID: "platform-client"})
	finder := appauth.NewCredentialFinder(adapters.NewAuthRepository(store), cache.NewTTLMapManager(time.Minute), slog.New(slog.DiscardHandler), defaultIdP)
	metadata := appoauth.NewMetadataService(finder, nil, nil, nil)
	ready := configsync.ReadinessCheck(store)
	register := func() error {
		_, err := metadata.RegisterClient(context.Background(), "https://gw.example.com", appoauth.RegisterRequest{
			RedirectURIs: []string{"https://client.example.com/cb"},
		})
		return err
	}

	if err := ready(context.Background()); !errors.Is(err, configsync.ErrNotReady) {
		t.Fatalf("readiness without a snapshot = %v, want ErrNotReady", err)
	}
	if err := register(); !errors.Is(err, authdomain.ErrNotFound) {
		t.Fatalf("registration without a snapshot = %v, want %v", err, authdomain.ErrNotFound)
	}

	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v1", Snapshot: &readmodel.Snapshot{}})

	if err := ready(context.Background()); err != nil {
		t.Fatalf("readiness with a snapshot = %v, want ready", err)
	}
	if err := register(); err != nil {
		t.Fatalf("registration with a snapshot = %v, want success", err)
	}
}
