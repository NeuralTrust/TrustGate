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

	// The events table has stored a single identifier under this attribute
	// since its end_user column was added; the fields below widen it.
	assert.Equal(t, "u-42", attrs[attrEndUser].AsString())
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
		attrEndUser, attrEndUserID, attrEndUserEmail, attrEndUserName, attrEndUserRole, attrEndUserSource,
	} {
		_, present := attrs[attr]
		assert.False(t, present, "%s must be absent when no end user was declared", attr)
	}
}

// A client that declares only an email or only a name still has to land in the
// single-identifier attribute, or those requests attribute to nobody.
func TestEventToRecord_EndUserIdentifierFallsBack(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		endUser events.EndUser
		want    string
	}{
		{"id wins", events.EndUser{ID: "u-42", Email: "ana@acme.test", Name: "Ana"}, "u-42"},
		{"email without id", events.EndUser{Email: "ana@acme.test", Name: "Ana"}, "ana@acme.test"},
		{"name alone", events.EndUser{Name: "Ana"}, "Ana"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evt := baseEndUserEvent()
			endUser := tc.endUser
			evt.EndUser = &endUser

			attrs := attrsOf(eventToRecord(evt))

			assert.Equal(t, tc.want, attrs[attrEndUser].AsString())
		})
	}
}

// Only a role is not an end user: it names nobody, so it must not create an
// attribution that a query would then group by.
func TestEventToRecord_EndUserIdentifierOmittedWhenNobodyIsNamed(t *testing.T) {
	t.Parallel()
	evt := baseEndUserEvent()
	evt.EndUser = &events.EndUser{Role: "admin", Source: "open_webui"}

	attrs := attrsOf(eventToRecord(evt))

	_, present := attrs[attrEndUser]
	assert.False(t, present, "%s must be absent when no id, email or name was declared", attrEndUser)
	assert.Equal(t, "admin", attrs[attrEndUserRole].AsString())
}
