package context

// StreamMetricsFinalizerKey is the fiber Locals key under which the metrics
// middleware stashes a StreamMetricsFinalizer for the proxy stream writer.
const StreamMetricsFinalizerKey = "__stream_metrics_finalizer"

// StreamMetricsOwnedKey is the fiber Locals key the proxy stream writer sets to
// signal that it owns the metrics emission for this request (via the
// finalizer). The middleware checks it on the way out and skips its own
// deferred emission, so a streamed request is emitted exactly once regardless
// of the response Content-Type.
const StreamMetricsOwnedKey = "__stream_metrics_owned"

// StreamMetricsFinalizer emits metrics for a streamed response once its SSE body
// has been fully written.
//
// The metrics middleware records request/response data on the way out via a
// deferred call, but a streamed body is flushed by fasthttp *after* the
// middleware returns, so at that point the captured output is empty. To close
// that gap the middleware stashes a finalizer in fiber Locals and skips its own
// emission for streaming responses; the proxy stream writer (which runs during
// body serialization) invokes the finalizer with the request context, the
// captured output bytes and the final response status/headers. The request
// context carries the observed token usage in its Metadata, which the metrics
// pipeline reads back when building the event.
type StreamMetricsFinalizer func(
	req *RequestContext,
	output []byte,
	statusCode int,
	headers map[string][]string,
)
