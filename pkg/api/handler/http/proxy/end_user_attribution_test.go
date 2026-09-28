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

package proxy

import (
	"errors"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

func TestEndUserAttribution(t *testing.T) {
	rc := &appconsumer.RoutableConsumer{Consumer: &domainconsumer.Consumer{Type: domainconsumer.TypeLLM}}

	// No opt-in any more: naming the person a call is for is the application's
	// to decide, per call.
	if got, err := endUserAttribution(rc, " user_123 "); err != nil || got != "user_123" {
		t.Fatalf("a named end user is recorded, trimmed, got %q %v", got, err)
	}
	if got, err := endUserAttribution(rc, ""); err != nil || got != "" {
		t.Fatalf("a missing header is not an error, got %q %v", got, err)
	}
	if _, err := endUserAttribution(rc, strings.Repeat("x", domainconsumer.MaxEndUserLength+1)); !errors.Is(err, appproxy.ErrInvalidRequestPayload) {
		t.Fatalf("a malformed id is rejected as a bad request, got %v", err)
	}
	if got, err := endUserAttribution(nil, "user"); err != nil || got != "" {
		t.Fatalf("no consumer, nothing to attribute, got %q %v", got, err)
	}
}
