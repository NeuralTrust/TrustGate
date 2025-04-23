package metrics

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	appTelemetry "github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/prometheus"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/NeuralTrust/TrustGate/pkg/utils"
	"github.com/sirupsen/logrus"
)

type Worker interface {
	Shutdown()
	StartWorkers(n int)
	Process(
		metricsCollector *Collector,
		exporters []types.Exporter,
		req *types.RequestContext,
		resp *types.ResponseContext,
		startTime time.Time,
		endTime time.Time,
	)
}

type worker struct {
	logger           *logrus.Logger
	providersBuilder appTelemetry.ExportersBuilder
	taskChan         chan func()
	ctx              context.Context
	cancel           context.CancelFunc
	closed           atomic.Bool
}

func NewWorker(logger *logrus.Logger, providersBuilder appTelemetry.ExportersBuilder) Worker {
	ctx, cancel := context.WithCancel(context.Background())
	m := &worker{
		logger:           logger,
		providersBuilder: providersBuilder,
		taskChan:         make(chan func(), 1000),
		ctx:              ctx,
		cancel:           cancel,
	}
	return m
}

func (m *worker) Shutdown() {
	m.closed.Store(true)
	m.logger.Info("shutting down metrics workers")
	m.cancel()
	close(m.taskChan)
	m.logger.Info("metrics workers stopped")
}

func (m *worker) Process(
	metricsCollector *Collector,
	exporters []types.Exporter,
	req *types.RequestContext,
	resp *types.ResponseContext,
	startTime,
	endTime time.Time,
) {
	m.enqueueTask(func() {
		m.registryMetricsToPrometheus(req.Method, req.GatewayID, resp.StatusCode)
	}, req.GatewayID)

	m.enqueueTask(func() {
		m.registryMetricsToExporters(metricsCollector, exporters, req, resp, startTime, endTime)
	}, req.GatewayID)
}

func (m *worker) registryMetricsToExporters(
	collector *Collector,
	exporters []types.Exporter,
	req *types.RequestContext,
	resp *types.ResponseContext,
	startTime,
	endTime time.Time,
) {
	exp, err := m.providersBuilder.Build(exporters)
	if err != nil {
		m.logger.WithError(err).Error("failed to build telemetry providers")
		return
	}
	events := collector.Flush()
	var failedExporters []string
	for _, exporter := range exp {
		defer exporter.Close()
		for _, metricsEvent := range events {
			err = exporter.Handle(context.Background(), m.feedEvent(metricsEvent, req, resp, startTime, endTime))
			if err != nil {
				m.logger.WithFields(logrus.Fields{
					"gatewayID":   req.GatewayID,
					"exporter":    fmt.Sprintf("%T", exporter),
					"event":       metricsEvent,
					"description": "failed to handle metrics event",
				}).WithError(err).Error("exporter failed")

				failedExporters = append(failedExporters, fmt.Sprintf("%T", exporter))
				break
			}
		}
	}
	if len(failedExporters) > 0 {
		m.logger.WithField("failedExporters", failedExporters).
			Warnf("%d exporters failed to handle metrics events", len(failedExporters))
	}
}

func (m *worker) registryMetricsToPrometheus(method, gatewayID string, statusCode int) {
	if prometheus.Config.EnableConnections {
		prometheus.GatewayConnections.WithLabelValues(gatewayID, "active").Inc()
	}
	status := m.getStatusClass(strconv.Itoa(statusCode))
	prometheus.GatewayRequestTotal.WithLabelValues(
		gatewayID,
		method,
		status,
	).Inc()
	if prometheus.Config.EnableConnections {
		prometheus.GatewayConnections.WithLabelValues(gatewayID, "active").Dec()
	}
}

func (m *worker) StartWorkers(n int) {
	fmt.Println("starting metrics workers...")
	for i := 0; i < n; i++ {
		go func(workerID int) {
			for {
				select {
				case task := <-m.taskChan:
					task()
				case <-m.ctx.Done():
					return
				}
			}
		}(i)
	}
}

func (m *worker) enqueueTask(task func(), gatewayID string) {
	if m.closed.Load() {
		return
	}
	select {
	case m.taskChan <- task:
	default:
		m.logger.WithField("gatewayID", gatewayID).
			Warn("taskChan is full, dropping metrics task")
	}
}

func (m *worker) feedEvent(
	evt *metric_events.Event,
	req *types.RequestContext,
	resp *types.ResponseContext,
	startTime, endTime time.Time,
) *metric_events.Event {
	elapsedTime := endTime.Sub(startTime)
	evt.StartTimestamp = startTime.Unix()
	evt.Latency = elapsedTime.Milliseconds()
	evt.IP = req.IP
	evt.Method = req.Method

	if conversationIDs, ok := req.Headers[common.ConversationIDHeader]; ok && len(conversationIDs) > 0 {
		evt.ConversationID = conversationIDs[0]
	}
	if interactionIDs, ok := req.Headers[common.InteractionIDHeader]; ok && len(interactionIDs) > 0 {
		evt.InteractionID = interactionIDs[0]
	}

	if userAgent, ok := req.Metadata["user_agent_info"]; ok {
		if ua, ok := userAgent.(*utils.UserAgentInfo); ok && ua != nil {
			evt.Browser = ua.Browser
			evt.Device = ua.Device
			evt.Os = ua.OS
			evt.Locale = ua.Locale
		}
	}
	evt.Input = string(req.Body)
	evt.Output = string(resp.Body)
	if evt.StatusCode == 0 {
		evt.StatusCode = resp.StatusCode
	}
	evt.RequestHeaders = req.Headers
	evt.ResponseHeaders = resp.Headers
	evt.EndTimestamp = endTime.Unix()
	return evt
}

func (m *worker) getStatusClass(status string) string {
	code, err := strconv.Atoi(status)
	if err != nil {
		return "5xx" // Return server error class if status code is invalid
	}
	return fmt.Sprintf("%dxx", code/100)
}
