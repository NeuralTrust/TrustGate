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

package outbox

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingAppender struct {
	appended []configsyncport.Marker
}

func (a *recordingAppender) AppendTx(context.Context, pgx.Tx) error {
	a.appended = append(a.appended, configsyncport.Marker{Kind: configsyncport.MarkerAll})
	return nil
}

func (a *recordingAppender) AppendGatewayTx(_ context.Context, _ pgx.Tx, gatewayID ids.GatewayID) error {
	a.appended = append(a.appended, configsyncport.Marker{Kind: configsyncport.MarkerGateway, GatewayID: gatewayID})
	return nil
}

func (a *recordingAppender) AppendCatalogTx(context.Context, pgx.Tx) error {
	a.appended = append(a.appended, configsyncport.Marker{Kind: configsyncport.MarkerCatalog})
	return nil
}

func TestMarksAppendWhatTheWriteRecorded(t *testing.T) {
	gwA, gwB := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	gatewayMarker := func(id ids.GatewayID) configsyncport.Marker {
		return configsyncport.Marker{Kind: configsyncport.MarkerGateway, GatewayID: id}
	}
	all := configsyncport.Marker{Kind: configsyncport.MarkerAll}
	catalog := configsyncport.Marker{Kind: configsyncport.MarkerCatalog}

	cases := []struct {
		name   string
		record func(*Marks)
		want   []configsyncport.Marker
	}{
		{name: "nothing recorded dirties everything", record: func(*Marks) {}, want: []configsyncport.Marker{all}},
		{name: "one gateway", record: func(m *Marks) { m.Gateway(gwA) }, want: []configsyncport.Marker{gatewayMarker(gwA)}},
		{name: "repeated gateways are deduplicated", record: func(m *Marks) { m.Gateway(gwA); m.Gateway(gwB); m.Gateway(gwA) }, want: []configsyncport.Marker{gatewayMarker(gwA), gatewayMarker(gwB)}},
		{name: "a nil gateway dirties everything", record: func(m *Marks) { m.Gateway(gwA); m.Gateway(ids.GatewayID{}) }, want: []configsyncport.Marker{all}},
		{name: "catalog", record: func(m *Marks) { m.Catalog() }, want: []configsyncport.Marker{catalog}},
		{name: "catalog and a gateway", record: func(m *Marks) { m.Catalog(); m.Gateway(gwA) }, want: []configsyncport.Marker{catalog, gatewayMarker(gwA)}},
		{name: "all wins over anything named", record: func(m *Marks) { m.Gateway(gwA); m.All() }, want: []configsyncport.Marker{all}},
		{name: "an unchanged write appends nothing", record: func(m *Marks) { m.Unchanged() }, want: nil},
		{name: "a named gateway wins over unchanged", record: func(m *Marks) { m.Unchanged(); m.Gateway(gwA) }, want: []configsyncport.Marker{gatewayMarker(gwA)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var marks Marks
			tc.record(&marks)
			appender := &recordingAppender{}
			require.NoError(t, marks.appendTo(context.Background(), nil, appender))
			assert.Equal(t, tc.want, appender.appended)
		})
	}
}

func TestMarksWithoutAppenderWriteNothing(t *testing.T) {
	var marks Marks
	marks.Gateway(ids.New[ids.GatewayKind]())
	require.NoError(t, marks.appendTo(context.Background(), nil, nil))
}

func TestDecodeMarker(t *testing.T) {
	gw := uuid.New()
	nilID := uuid.Nil
	str := func(s string) *string { return &s }

	cases := []struct {
		name      string
		kind      *string
		gatewayID *uuid.UUID
		want      configsyncport.Marker
	}{
		{name: "row from an admin that predates the columns", want: configsyncport.Marker{Seq: 7, Kind: configsyncport.MarkerAll}},
		{name: "gateway", kind: str("gateway"), gatewayID: &gw, want: configsyncport.Marker{Seq: 7, Kind: configsyncport.MarkerGateway, GatewayID: ids.From[ids.GatewayKind](gw)}},
		{name: "gateway without an id", kind: str("gateway"), want: configsyncport.Marker{Seq: 7, Kind: configsyncport.MarkerAll}},
		{name: "gateway with a nil id", kind: str("gateway"), gatewayID: &nilID, want: configsyncport.Marker{Seq: 7, Kind: configsyncport.MarkerAll}},
		{name: "catalog", kind: str("catalog"), want: configsyncport.Marker{Seq: 7, Kind: configsyncport.MarkerCatalog}},
		{name: "all", kind: str("all"), want: configsyncport.Marker{Seq: 7, Kind: configsyncport.MarkerAll}},
		{name: "unknown kind from a newer admin", kind: str("tenant_caps"), want: configsyncport.Marker{Seq: 7, Kind: configsyncport.MarkerAll}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, decodeMarker(7, tc.kind, tc.gatewayID))
		})
	}
}
