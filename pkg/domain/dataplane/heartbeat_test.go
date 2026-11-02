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

package dataplane_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	"github.com/stretchr/testify/assert"
)

func TestReportableURL(t *testing.T) {
	cases := map[string]string{
		"https://trustguard.eu.example.com":                          "https://trustguard.eu.example.com",
		"https://trustguard.eu.example.com/":                         "https://trustguard.eu.example.com",
		" http://trustguard-data.trustguard.svc.cluster.local:8081 ": "http://trustguard-data.trustguard.svc.cluster.local:8081",
		"https://user:secret@guard.example.com/base/?token=abc#frag": "https://guard.example.com/base",
		"https://guard.example.com/t/not-stripped":                   "https://guard.example.com/t/not-stripped",
		"":                    "",
		"guard.example.com":   "",
		"ftp://guard.example": "",
		"https://":            "",
		"://bad url":          "",
	}
	for raw, want := range cases {
		assert.Equal(t, want, dataplane.ReportableURL(raw), "ReportableURL(%q)", raw)
	}
}

func TestKnownDeploymentType(t *testing.T) {
	for in, want := range map[string]string{
		"saas":        "saas",
		"self-hosted": "self-hosted",
		"SaaS":        "",
		"hybrid":      "",
		"":            "",
	} {
		assert.Equal(t, want, dataplane.KnownDeploymentType(in), "KnownDeploymentType(%q)", in)
	}
}
