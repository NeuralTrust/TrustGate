package cache

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type TLSClientCache struct {
	logger *logrus.Logger
}

func NewTLSClientCache(logger *logrus.Logger) *TLSClientCache {
	return &TLSClientCache{
		logger: logger,
	}
}

func (c *TLSClientCache) GetOrCreate(key string, cfg *tls.Config, proxyAddr string, proxyProtocol string) *fasthttp.Client {
	// Create a new client each time - no caching to avoid connection reuse issues
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
			// targetNeedsTLS indicates whether the final destination requires TLS (based on port 443)
			targetNeedsTLS := false
			// proxyNeedsTLS indicates whether the connection to the proxy itself needs TLS
			proxyNeedsTLS := proxyProtocol == "https"

			if strings.Contains(addr, ":") {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address format: %w", err)
				}

				// Determine if target needs TLS based on port
				targetNeedsTLS = port == "443"
				hostPort = net.JoinHostPort(host, port)
			} else {
				// Default ports based on common patterns
				hostPort = net.JoinHostPort(addr, "80")
				targetNeedsTLS = false
			}

			// Connect to the proxy
			var proxyConn net.Conn
			var err error

			if proxyNeedsTLS {
				// Connect to proxy using TLS
				proxyConn, err = tls.Dial("tcp", proxyAddr, &tls.Config{
					InsecureSkipVerify: true, // #nosec G402 - proxy connections may use self-signed certs
				})
			} else {
				// Connect to proxy using plain TCP
				proxyConn, err = net.Dial("tcp", proxyAddr)
			}

			if err != nil {
				c.logger.WithFields(logrus.Fields{
					"proxy_addr":      proxyAddr,
					"proxy_needs_tls": proxyNeedsTLS,
					"error":           err.Error(),
				}).Debug("proxy connection failed")
				return nil, fmt.Errorf("failed to connect to proxy: %w", err)
			}

			c.logger.WithFields(logrus.Fields{
				"proxy_addr":       proxyAddr,
				"proxy_needs_tls":  proxyNeedsTLS,
				"target_needs_tls": targetNeedsTLS,
			}).Debug("proxy connection established successfully")

			// If the target needs TLS, we need to establish a CONNECT tunnel through the proxy
			if targetNeedsTLS {
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

	return client
}
