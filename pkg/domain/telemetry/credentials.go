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

package telemetry

import (
	"fmt"
	"reflect"
	"strings"
)

// ExporterTypeOTLP and ExporterTypePostgres are the exporter types whose
// settings carry credentials: the OTLP headers and the postgres dsn.
const (
	ExporterTypeOTLP     = "otlp"
	ExporterTypePostgres = "postgres"
)

const (
	headersKey = "headers"
	dsnKey     = "dsn"
)

// otlpDestinationKeys decide where OTLP headers are sent. Stored headers are
// only carried over while none of them changes, so a caller who never read
// the headers cannot redirect them to a collector of their choosing.
var otlpDestinationKeys = []string{"endpoint", "insecure", "tls"}

// WithoutCredentials returns a copy of t with the credential settings removed:
// the OTLP headers and the postgres dsn. t is never modified, since the same
// value drives the live exporters.
func (t *Telemetry) WithoutCredentials() *Telemetry {
	if t == nil {
		return nil
	}
	out := *t
	if t.Exporters == nil {
		return &out
	}
	out.Exporters = make([]ExporterConfig, len(t.Exporters))
	for i, exporter := range t.Exporters {
		if key, ok := credentialKey(exporter.EffectiveType()); ok {
			exporter.Settings = withoutKey(exporter.Settings, key)
		}
		out.Exporters[i] = exporter
	}
	return &out
}

// KeepOmittedCredentials carries the stored credential settings into incoming,
// which the caller owns and which is modified in place. Reads never return
// credentials, so a read-modify-write sends the exporters back without them;
// an update replaces telemetry wholesale and would otherwise clear them.
//
// An exporter is matched to the stored one by name and type. A credential the
// incoming exporter omits is copied from the stored one; one it sends, even
// empty, replaces it, and an explicit null clears it. OTLP headers are only
// copied while the endpoint, insecure and tls settings are unchanged: a
// caller changing any of them must send the headers again, or {} for none.
func KeepOmittedCredentials(incoming, stored *Telemetry) error {
	if incoming == nil {
		return nil
	}
	for i := range incoming.Exporters {
		exporter := &incoming.Exporters[i]
		key, ok := credentialKey(exporter.EffectiveType())
		if !ok {
			continue
		}
		if _, sent := foldValue(exporter.Settings, key); sent {
			exporter.Settings = withoutNull(exporter.Settings, key)
			continue
		}
		previous := storedSettings(stored, exporter.Name, exporter.EffectiveType())
		value, found := foldValue(previous, key)
		if !found || value == nil {
			continue
		}
		if exporter.EffectiveType() == ExporterTypeOTLP {
			for _, destination := range otlpDestinationKeys {
				if !foldEqual(exporter.Settings, previous, destination) {
					return fmt.Errorf("exporter %q: send settings.headers again when changing settings.%s", exporter.Name, destination)
				}
			}
		}
		if exporter.Settings == nil {
			exporter.Settings = make(map[string]any, 1)
		}
		exporter.Settings[key] = value
	}
	return nil
}

func credentialKey(exporterType string) (string, bool) {
	switch exporterType {
	case ExporterTypeOTLP:
		return headersKey, true
	case ExporterTypePostgres:
		return dsnKey, true
	default:
		return "", false
	}
}

func storedSettings(stored *Telemetry, name, exporterType string) map[string]any {
	if stored == nil {
		return nil
	}
	for _, exporter := range stored.Exporters {
		if exporter.Name == name && exporter.EffectiveType() == exporterType {
			return exporter.Settings
		}
	}
	return nil
}

// withoutKey drops every key equal to name under case folding: settings are
// decoded with mapstructure, which matches keys case-insensitively, so a
// "Headers" key is used exactly like "headers".
func withoutKey(settings map[string]any, name string) map[string]any {
	if _, ok := foldValue(settings, name); !ok {
		return settings
	}
	out := make(map[string]any, len(settings))
	for k, v := range settings {
		if !strings.EqualFold(k, name) {
			out[k] = v
		}
	}
	return out
}

func withoutNull(settings map[string]any, name string) map[string]any {
	for k, v := range settings {
		if v == nil && strings.EqualFold(k, name) {
			delete(settings, k)
		}
	}
	return settings
}

func foldValue(m map[string]any, name string) (any, bool) {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return nil, false
}

func foldEqual(a, b map[string]any, name string) bool {
	av, aok := foldValue(a, name)
	bv, bok := foldValue(b, name)
	return aok == bok && reflect.DeepEqual(av, bv)
}
