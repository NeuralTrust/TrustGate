package logger

import (
	"context"
	"log/slog"
	"sync"
)

// AsyncHandler estructura para manejar logs de forma asíncrona
type AsyncHandler struct {
	handler slog.Handler
	logChan chan slog.Record
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewAsyncHandler inicializa un AsyncHandler con un buffer
func NewAsyncHandler(inner slog.Handler, bufferSize int) *AsyncHandler {
	h := &AsyncHandler{
		handler: inner,
		logChan: make(chan slog.Record, bufferSize),
		done:    make(chan struct{}),
	}

	// Iniciar la goroutine para procesar logs en segundo plano
	h.wg.Add(1)
	go h.processLogs()

	return h
}

// Handle envía los logs al canal de manera asíncrona
func (h *AsyncHandler) Handle(ctx context.Context, r slog.Record) error {
	select {
	case h.logChan <- r: // Enviar el log al canal sin bloquear
	default:
		// Evitar bloqueos si el canal está lleno (descartar logs más viejos)
	}
	return nil
}

// Enabled verifica si el nivel de log está habilitado
func (h *AsyncHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level) // Delegar al handler interno
}

// WithAttrs permite agregar atributos adicionales al handler
func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AsyncHandler{
		handler: h.handler.WithAttrs(attrs), // Delegar a la implementación base
		logChan: h.logChan,
		done:    h.done,
	}
}

// WithGroup permite agrupar logs
func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	return &AsyncHandler{
		handler: h.handler.WithGroup(name), // Delegar a la implementación base
		logChan: h.logChan,
		done:    h.done,
	}
}

// processLogs maneja la escritura en consola de forma asíncrona
func (h *AsyncHandler) processLogs() {
	defer h.wg.Done()

	for {
		select {
		case logRecord := <-h.logChan:
			h.handler.Handle(context.Background(), logRecord) // Escribir log
		case <-h.done:
			// Procesar logs pendientes antes de cerrar
			for len(h.logChan) > 0 {
				h.handler.Handle(context.Background(), <-h.logChan)
			}
			return
		}
	}
}

// Close cierra el handler de manera segura
func (h *AsyncHandler) Close() {
	close(h.done)
	h.wg.Wait()
}
