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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ appmetrics.Exporter = (*Exporter)(nil)

var errExporterClosed = errors.New("postgres: exporter is closed")

// writeTimeout bounds a single insert so a slow or hung sensible DB cannot stall
// the metrics worker goroutine that drives Publish.
const writeTimeout = 10 * time.Second

// Exporter persists the sensible view of an event (request and response bodies
// only) into the owner-controlled Postgres store. It is sensible-only and can
// never be reused as a metadata sink.
type Exporter struct {
	pool      *pgxpool.Pool
	insertSQL string
	logger    *slog.Logger
	closed    atomic.Bool
}

func newExporter(pool *pgxpool.Pool, table string, logger *slog.Logger) *Exporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Exporter{
		pool:      pool,
		insertSQL: buildInsertSQL(table),
		logger:    logger,
	}
}

func (e *Exporter) Name() string {
	return ExporterName
}

// DataClass fixes this exporter to the sensible class; the pipeline uses it to
// route only the sensible view here (ENG-1021).
func (e *Exporter) DataClass() metrics.DataClass {
	return metrics.Raw
}

// Publish writes the sensible projection of the event as one row. The write is
// idempotent on trace_id so a retried event does not duplicate a row.
func (e *Exporter) Publish(ctx context.Context, evt *events.Event) error {
	if evt == nil {
		return nil
	}
	if e.closed.Load() {
		return errExporterClosed
	}
	rec := toRecord(evt.SensibleView())
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if _, err := e.pool.Exec(ctx, e.insertSQL,
		rec.TraceID,
		rec.GatewayID,
		rec.TeamID,
		rec.OccurredOn,
		rec.SchemaVersion,
		rec.RequestBody,
		rec.ResponseBody,
	); err != nil {
		return fmt.Errorf("postgres: insert sensible record: %w", err)
	}
	return nil
}

// Close releases the connection pool exactly once; further Publish calls fail
// fast rather than touching a closed pool.
func (e *Exporter) Close() {
	if e.pool == nil || !e.closed.CompareAndSwap(false, true) {
		return
	}
	e.pool.Close()
}

func toRecord(view events.Event) metrics.SensibleRecord {
	rec := metrics.SensibleRecord{
		TraceID:       view.TraceID,
		GatewayID:     view.GatewayID,
		OccurredOn:    view.OccurredOn,
		SchemaVersion: metrics.SchemaVersion,
		RequestBody:   view.Request.Body,
		ResponseBody:  view.Response.Body,
	}
	if team := strings.TrimSpace(view.TeamID); team != "" {
		rec.TeamID = &team
	}
	return rec
}

func buildInsertSQL(table string) string {
	cols := metrics.InsertColumns()
	placeholders := make([]string, len(cols))
	for i := range cols {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	return fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING",
		table,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
		metrics.ColumnTraceID,
	)
}
