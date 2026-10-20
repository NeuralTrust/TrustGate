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
	"testing"
	"time"
)

func TestLoadConfig_UsageRecordsDisabledByDefault(t *testing.T) {
	minimumEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.UsageRecords.Enabled {
		t.Error("UsageRecords.Enabled default = true, want false")
	}
	if cfg.UsageRecords.QueueSize != defaultUsageRecordsQueue {
		t.Errorf("UsageRecords.QueueSize default = %d, want %d", cfg.UsageRecords.QueueSize, defaultUsageRecordsQueue)
	}
}

func TestLoadConfig_UsageRecordsOverrides(t *testing.T) {
	minimumEnv(t)
	t.Setenv("USAGE_RECORDS_ENABLED", "true")
	t.Setenv("USAGE_RECORDS_QUEUE_SIZE", "10")
	t.Setenv("USAGE_RECORDS_OTLP_ENDPOINT", "https://ingest.example.com/v1/logs")
	t.Setenv("USAGE_RECORDS_OTLP_PROTOCOL", "http/protobuf")
	t.Setenv("USAGE_RECORDS_OTLP_HEADERS", "authorization=Bearer usage")
	t.Setenv("USAGE_RECORDS_OTLP_TIMEOUT", "3s")
	t.Setenv("USAGE_RECORDS_OTLP_INSECURE", "true")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	u := cfg.UsageRecords
	if !u.Enabled || u.QueueSize != 10 {
		t.Errorf("UsageRecords = %+v", u)
	}
	if u.OTLP.Endpoint != "https://ingest.example.com/v1/logs" || u.OTLP.Protocol != "http/protobuf" {
		t.Errorf("UsageRecords.OTLP endpoint/protocol = %q/%q", u.OTLP.Endpoint, u.OTLP.Protocol)
	}
	if u.OTLP.Headers["authorization"] != "Bearer usage" {
		t.Errorf("UsageRecords.OTLP.Headers = %v", u.OTLP.Headers)
	}
	if u.OTLP.Timeout != 3*time.Second || !u.OTLP.Insecure {
		t.Errorf("UsageRecords.OTLP timeout/insecure = %v/%v", u.OTLP.Timeout, u.OTLP.Insecure)
	}
}

func TestLoadConfig_UsageRecordsValidation(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{
			name:    "enabled without any endpoint",
			env:     map[string]string{"USAGE_RECORDS_ENABLED": "true"},
			wantErr: true,
		},
		{
			name: "enabled with the operator endpoint",
			env: map[string]string{
				"USAGE_RECORDS_ENABLED":       "true",
				"OTEL_EXPORTER_OTLP_ENDPOINT": "collector:4318",
			},
		},
		{
			name: "enabled with its own endpoint",
			env: map[string]string{
				"USAGE_RECORDS_ENABLED":       "true",
				"USAGE_RECORDS_OTLP_ENDPOINT": "collector:4317",
			},
		},
		{
			name: "enabled with an empty queue",
			env: map[string]string{
				"USAGE_RECORDS_ENABLED":       "true",
				"USAGE_RECORDS_OTLP_ENDPOINT": "collector:4317",
				"USAGE_RECORDS_QUEUE_SIZE":    "0",
			},
			wantErr: true,
		},
		{
			name: "disabled ignores an empty queue",
			env:  map[string]string{"USAGE_RECORDS_QUEUE_SIZE": "0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minimumEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			_, err := LoadConfig()
			if tt.wantErr && err == nil {
				t.Fatal("LoadConfig accepted the config")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
		})
	}
}
