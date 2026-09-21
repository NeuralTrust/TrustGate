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

package otlp

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
)

func baseEndUserEvent() *events.Event {
	return &events.Event{
		SchemaVersion: events.SchemaVersion,
		TraceID:       "trace-end-user",
		GatewayID:     "gw-1",
		TenantID:      "team-1",
		Status:        events.Status{Code: 200},
		Request:       events.Request{Method: "POST", Path: "/v1/chat/completions"},
		Response:      events.Response{StatusCode: 200},
	}
}

func TestEventToRecord_EndUserAttributes(t *testing.T) {
	t.Parallel()
	evt := baseEndUserEvent()
	evt.PrincipalSubject = "shared-api-key"
	evt.PrincipalMethod = "api_key"
	evt.EndUser = &events.EndUser{
		ID:     "u-42",
		Email:  "ana@acme.test",
		Name:   "Ana",
		Role:   "admin",
		Source: "open_webui",
	}

	attrs := attrsOf(eventToRecord(evt))

	assert.Equal(t, "u-42", attrs[attrEndUserID].AsString())
	assert.Equal(t, "ana@acme.test", attrs[attrEndUserEmail].AsString())
	assert.Equal(t, "Ana", attrs[attrEndUserName].AsString())
	assert.Equal(t, "admin", attrs[attrEndUserRole].AsString())
	assert.Equal(t, "open_webui", attrs[attrEndUserSource].AsString())
	// The credential that actually authenticated stays its own attribute: a
	// reader must be able to tell the two apart downstream.
	assert.Equal(t, "shared-api-key", attrs[attrPrincipalSubject].AsString())
	assert.Equal(t, "api_key", attrs[attrPrincipalMethod].AsString())
}

func TestEventToRecord_OmitsEndUserAttributesWhenAbsent(t *testing.T) {
	t.Parallel()
	attrs := attrsOf(eventToRecord(baseEndUserEvent()))

	for _, attr := range []string{
		attrEndUserID, attrEndUserEmail, attrEndUserName, attrEndUserRole, attrEndUserSource,
	} {
		_, present := attrs[attr]
		assert.False(t, present, "%s must be absent when no end user was declared", attr)
	}
}
