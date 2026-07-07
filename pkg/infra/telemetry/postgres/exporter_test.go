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

package postgres

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataClassIsRaw(t *testing.T) {
	t.Parallel()
	assert.Equal(t, metrics.Raw, (&Exporter{}).DataClass())
}

func TestBuildInsertSQL(t *testing.T) {
	t.Parallel()
	want := "INSERT INTO " + metrics.TableName + " (trace_id, gateway_id, team_id, occurred_on, schema_version, request_body, response_body) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (trace_id) DO NOTHING"
	assert.Equal(t, want, buildInsertSQL(metrics.TableName))
}

func TestToRecordMapsSensibleViewAndStampsSchemaVersion(t *testing.T) {
	t.Parallel()

	resp := "resp-body"
	evt := events.Event{
		SchemaVersion: events.SchemaVersion,
		TraceID:       "t1",
		GatewayID:     "g1",
		TeamID:        "team1",
		OccurredOn:    42,
		IP:            "1.2.3.4",
		Request:       events.Request{Body: "req-body", Headers: map[string][]string{"h": {"v"}}},
		Response:      events.Response{Body: &resp, StatusCode: 200},
	}

	rec := toRecord(evt.SensibleView())

	assert.Equal(t, "t1", rec.TraceID)
	assert.Equal(t, "g1", rec.GatewayID)
	require.NotNil(t, rec.TeamID)
	assert.Equal(t, "team1", *rec.TeamID)
	assert.Equal(t, int64(42), rec.OccurredOn)
	assert.Equal(t, metrics.SchemaVersion, rec.SchemaVersion)
	assert.Equal(t, "req-body", rec.RequestBody)
	require.NotNil(t, rec.ResponseBody)
	assert.Equal(t, "resp-body", *rec.ResponseBody)
}

func TestToRecordNilTeamAndResponse(t *testing.T) {
	t.Parallel()

	evt := events.Event{TraceID: "t2", GatewayID: "g2", Request: events.Request{Body: ""}}

	rec := toRecord(evt.SensibleView())

	assert.Nil(t, rec.TeamID)
	assert.Nil(t, rec.ResponseBody)
	assert.Empty(t, rec.RequestBody)
}

func TestPublishOnClosedExporterFails(t *testing.T) {
	t.Parallel()

	e := &Exporter{}
	e.closed.Store(true)

	err := e.Publish(context.Background(), &events.Event{TraceID: "x"})
	require.ErrorIs(t, err, errExporterClosed)
}

func TestPublishNilEventIsNoop(t *testing.T) {
	t.Parallel()
	require.NoError(t, (&Exporter{}).Publish(context.Background(), nil))
}

func TestCloseWithoutPoolIsSafe(t *testing.T) {
	t.Parallel()
	(&Exporter{}).Close()
}
