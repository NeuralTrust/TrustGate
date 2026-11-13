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

package secretref

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
)

// exporterDestinationKeys decide where an exporter's credentials go: the
// OTLP collector and how it is reached. A postgres dsn names its own host.
var exporterDestinationKeys = []string{"endpoint", "insecure", "tls"}

// GatewayRefs lists the telemetry exporter credentials of gw (OTLP headers,
// postgres dsn) that hold a reference or embed one, and where they go.
func GatewayRefs(gw *gateway.Gateway) EntityRefs {
	refs := EntityRefs{GatewayID: gw.ID, Entity: domain.EntityGateway, ID: gw.ID.String(), Gateway: gw}
	if gw.Telemetry == nil {
		return refs
	}
	uses, embedded, dest := exporterRefs(gw.Telemetry.Exporters)
	refs.Uses, refs.Embedded, refs.Destination = uses, embedded, dest
	return refs
}

func exporterRefs(exporters []telemetry.ExporterConfig) (uses, embedded []Use, destination string) {
	var dest []string
	for _, e := range exporters {
		visit := func(value any, path []string) {
			s, ok := value.(string)
			if !ok {
				return
			}
			switch {
			case domain.IsRef(s):
				uses = append(uses, Use{Path: path, Raw: s})
			case domain.ContainsRef(s):
				embedded = append(embedded, Use{Path: path, Raw: s})
			}
		}
		base := []string{"telemetry", "exporters", e.Name, "settings"}
		for key, value := range e.Settings {
			switch {
			case strings.EqualFold(key, "headers"):
				for name, h := range stringMap(value) {
					visit(h, append(append([]string(nil), base...), "headers", name))
				}
			case strings.EqualFold(key, "dsn"):
				visit(value, append(append([]string(nil), base...), "dsn"))
			}
		}
		parts := []string{e.Name, e.EffectiveType()}
		for _, k := range exporterDestinationKeys {
			for key, value := range e.Settings {
				if strings.EqualFold(key, k) {
					parts = append(parts, k+"="+fmt.Sprint(value))
				}
			}
		}
		dest = append(dest, strings.Join(parts, "\x00"))
	}
	sort.Strings(dest)
	return uses, embedded, strings.Join(dest, "\x01")
}

// GatewayExporters returns exporters with every reference at a credential
// location replaced by its resolved value, or an empty one where it does not
// resolve, on copies; it records what the gateway's exporters use, so a
// change invalidates the gateway. The input is never modified.
func GatewayExporters(ctx context.Context, r ValuesResolver, gatewayID ids.GatewayID, exporters []telemetry.ExporterConfig) []telemetry.ExporterConfig {
	uses, _, _ := exporterRefs(exporters)
	resolved := r.Values(ctx, gatewayID, SourceGateway, uses)
	if len(uses) == 0 {
		return exporters
	}
	byExporter := map[string]map[string]string{}
	for i, u := range uses {
		name, rest := u.Path[2], strings.Join(u.Path[4:], "\x00")
		if byExporter[name] == nil {
			byExporter[name] = map[string]string{}
		}
		byExporter[name][rest] = resolved[i].Value
	}
	out := make([]telemetry.ExporterConfig, len(exporters))
	for i, e := range exporters {
		out[i] = e
		set, ok := byExporter[e.Name]
		if !ok {
			continue
		}
		settings := make(map[string]any, len(e.Settings))
		for key, value := range e.Settings {
			switch {
			case strings.EqualFold(key, "headers"):
				headers := stringMap(value)
				copied := make(map[string]any, len(headers))
				for name, h := range headers {
					if v, ok := set["headers\x00"+name]; ok {
						copied[name] = v
					} else {
						copied[name] = h
					}
				}
				settings[key] = copied
			case strings.EqualFold(key, "dsn"):
				if v, ok := set["dsn"]; ok {
					settings[key] = v
				} else {
					settings[key] = value
				}
			default:
				settings[key] = value
			}
		}
		out[i].Settings = settings
	}
	return out
}

// stringMap reads a headers setting decoded from JSON or built in code.
func stringMap(value any) map[string]any {
	switch m := value.(type) {
	case map[string]any:
		return m
	case map[string]string:
		out := make(map[string]any, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	return nil
}
