package trace

import "context"

type contextKey string

const traceContextKey contextKey = "__request_trace"

func NewContext(ctx context.Context, t *RequestTrace) context.Context {
	return context.WithValue(ctx, traceContextKey, t)
}

func FromContext(ctx context.Context) *RequestTrace {
	if ctx == nil {
		return nil
	}
	t, _ := ctx.Value(traceContextKey).(*RequestTrace)
	return t
}
