package cache

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
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

func (c *TLSClientCache) GetOrCreate(key string, cfg *tls.Config, proxyAddr string) *fasthttp.Client {

	if cl, ok := c.clients.Load(key); ok {
		if typedClient, ok := cl.(*fasthttp.Client); ok {
			return typedClient
		}
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

	if proxyAddr != "" {
		client.Dial = func(addr string) (net.Conn, error) {
			hostPort := addr
			isTLS := false

			if strings.Contains(addr, ":") {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address format: %w", err)
				}

				// Default HTTPS port is 443
				if port == "443" {
					isTLS = true
				}

				hostPort = net.JoinHostPort(host, port)
			} else {
				// If no port is specified, assume it's HTTPS (port 443)
				hostPort = net.JoinHostPort(addr, "443")
				isTLS = true
			}

			// Connect to the proxy
			proxyConn, err := net.Dial("tcp", proxyAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to connect to proxy: %w", err)
			}

			// For HTTPS connections, we need to establish a tunnel using the CONNECT method
			if isTLS {
				// Send the CONNECT request
				connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort)
				if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
					proxyConn.Close()
					return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
				}

				// Read the response
				br := bufio.NewReader(proxyConn)
				resp, err := br.ReadString('\n')
				if err != nil {
					proxyConn.Close()
					return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
				}

				// Check if the connection was established successfully
				if !strings.HasPrefix(resp, "HTTP/1.1 200") && !strings.HasPrefix(resp, "HTTP/1.0 200") {
					proxyConn.Close()
					return nil, fmt.Errorf("proxy CONNECT failed: %s", resp)
				}

				// Skip the rest of the headers
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						proxyConn.Close()
						return nil, fmt.Errorf("failed to read CONNECT response headers: %w", err)
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
			}
			return proxyConn, nil
		}
	}

	c.clients.Store(key, client)
	return client
}
