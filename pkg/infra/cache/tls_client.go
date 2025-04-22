package cache

import (
	"crypto/tls"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

type TLSClientCache struct {
	clients sync.Map
}

func NewTLSClientCache() *TLSClientCache {
	return &TLSClientCache{}
}

func (c *TLSClientCache) GetOrCreate(key string, cfg *tls.Config) *fasthttp.Client {
	if client, ok := c.clients.Load(key); ok {
		return client.(*fasthttp.Client)
	}
	client := &fasthttp.Client{
		TLSConfig:                     cfg,
		ReadTimeout:                   30 * time.Second,
		WriteTimeout:                  30 * time.Second,
		MaxConnsPerHost:               16384,
		MaxIdleConnDuration:           120 * time.Second,
		ReadBufferSize:                32768,
		WriteBufferSize:               32768,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
	}
	c.clients.Store(key, client)
	return client
}
