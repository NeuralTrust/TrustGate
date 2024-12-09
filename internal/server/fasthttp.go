package server

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

var (
	// FastHTTP client for better performance
	fastClient = &fasthttp.Client{
		MaxConnsPerHost:               5000,
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  5 * time.Second,
		MaxIdleConnDuration:           60 * time.Second,
		MaxConnDuration:               60 * time.Second,
		MaxResponseBodySize:           10 * 1024 * 1024,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
	}

	// Request pools
	requestPool  = &fasthttp.RequestCtx{}
	responsePool = &fasthttp.Response{}

	// Buffer pool for response bodies
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}
)

// Add proper log formatting
func logRequest(logger *logrus.Logger, ctx *fasthttp.RequestCtx, requestID, gatewayID string) {
	logger.WithFields(logrus.Fields{
		"request_id": requestID,
		"method":     string(ctx.Method()),
		"path":       string(ctx.Path()),
		"gateway_id": gatewayID,
		// Add other relevant fields...
	}).Info("Processing request")
}
