package cache

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type TLSClientCache struct {
	clients sync.Map
	logger  *logrus.Logger
}

func NewTLSClientCache(logger *logrus.Logger) *TLSClientCache {
	return &TLSClientCache{
		logger: logger,
	}
}

func (c *TLSClientCache) GetOrCreate(key string, cfg *tls.Config, proxyAddr string, proxyProtocol string) *fasthttp.Client {

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
			var hostPort string
			isTLS := false

			if strings.Contains(addr, ":") {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address format: %w", err)
				}

				if proxyProtocol != "" {
					isTLS = proxyProtocol == "https"
				} else {
					isTLS = port == "443"
				}

				hostPort = net.JoinHostPort(host, port)
			} else {
				if proxyProtocol == "https" {
					hostPort = net.JoinHostPort(addr, "443")
					isTLS = true
				} else {
					hostPort = net.JoinHostPort(addr, "80")
					isTLS = false
				}
			}

			proxyConn, err := net.Dial("tcp", proxyAddr)
			if err != nil {
				c.logger.WithFields(logrus.Fields{
					"proxy_addr": proxyAddr,
					"error":      err.Error(),
				}).Debug("proxy connection failed")
				return nil, fmt.Errorf("failed to connect to proxy: %w", err)
			}

			c.logger.WithFields(logrus.Fields{
				"proxy_addr": proxyAddr,
			}).Debug("proxy connection established successfully")

			if isTLS {
				connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort)
				if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
					closeErr := proxyConn.Close()
					if closeErr != nil {
						return nil, fmt.Errorf("failed to send CONNECT request: %w, close error: %v", err, closeErr)
					}
					return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
				}

				// Read the response
				br := bufio.NewReader(proxyConn)
				resp, err := br.ReadString('\n')
				if err != nil {
					closeErr := proxyConn.Close()
					if closeErr != nil {
						return nil, fmt.Errorf("failed to read CONNECT response: %w, close error: %v", err, closeErr)
					}
					return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
				}

				// Check if the connection was established successfully
				if !strings.HasPrefix(resp, "HTTP/1.1 200") && !strings.HasPrefix(resp, "HTTP/1.0 200") {
					c.logger.WithFields(logrus.Fields{
						"proxy_addr": proxyAddr,
						"host_port":  hostPort,
						"response":   strings.TrimSpace(resp),
					}).Debug("proxy CONNECT request failed")
					closeErr := proxyConn.Close()
					if closeErr != nil {
						return nil, fmt.Errorf("proxy CONNECT failed: %s, close error: %v", resp, closeErr)
					}
					return nil, fmt.Errorf("proxy CONNECT failed: %s", resp)
				}

				c.logger.WithFields(logrus.Fields{
					"proxy_addr": proxyAddr,
					"host_port":  hostPort,
				}).Debug("proxy CONNECT request successful")

				// Skip the rest of the headers
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						closeErr := proxyConn.Close()
						if closeErr != nil {
							return nil, fmt.Errorf("failed to read CONNECT response headers: %w, close error: %v", err, closeErr)
						}
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
