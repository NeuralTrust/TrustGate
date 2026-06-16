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

package cache

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

type TLSClientCache struct {
	logger *slog.Logger
}

func NewTLSClientCache(logger *slog.Logger) *TLSClientCache {
	return &TLSClientCache{
		logger: logger,
	}
}

func (c *TLSClientCache) GetOrCreate(key string, cfg *tls.Config, proxyAddr string, proxyProtocol string) *fasthttp.Client {
	_ = key

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
			targetNeedsTLS := false
			proxyNeedsTLS := proxyProtocol == "https"

			if strings.Contains(addr, ":") {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address format: %w", err)
				}
				targetNeedsTLS = port == "443"
				hostPort = net.JoinHostPort(host, port)
			} else {
				hostPort = net.JoinHostPort(addr, "80")
				targetNeedsTLS = false
			}

			var proxyConn net.Conn
			var err error

			if proxyNeedsTLS {
				proxyConn, err = tls.Dial("tcp", proxyAddr, &tls.Config{
					InsecureSkipVerify: true, // #nosec G402 -- proxy connections may use self-signed certs
				})
			} else {
				proxyConn, err = net.Dial("tcp", proxyAddr)
			}

			if err != nil {
				c.logger.Debug("proxy connection failed",
					slog.String("proxy_addr", proxyAddr),
					slog.Bool("proxy_needs_tls", proxyNeedsTLS),
					slog.String("error", err.Error()),
				)
				return nil, fmt.Errorf("failed to connect to proxy: %w", err)
			}

			c.logger.Debug("proxy connection established successfully",
				slog.String("proxy_addr", proxyAddr),
				slog.Bool("proxy_needs_tls", proxyNeedsTLS),
				slog.Bool("target_needs_tls", targetNeedsTLS),
			)

			if targetNeedsTLS {
				connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort)
				if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
					if closeErr := proxyConn.Close(); closeErr != nil {
						return nil, fmt.Errorf("failed to send CONNECT request: %w, close error: %v", err, closeErr)
					}
					return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
				}

				br := bufio.NewReader(proxyConn)
				resp, err := br.ReadString('\n')
				if err != nil {
					if closeErr := proxyConn.Close(); closeErr != nil {
						return nil, fmt.Errorf("failed to read CONNECT response: %w, close error: %v", err, closeErr)
					}
					return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
				}

				if !strings.HasPrefix(resp, "HTTP/1.1 200") && !strings.HasPrefix(resp, "HTTP/1.0 200") {
					c.logger.Debug("proxy CONNECT request failed",
						slog.String("proxy_addr", proxyAddr),
						slog.String("host_port", hostPort),
						slog.String("response", strings.TrimSpace(resp)),
					)
					if closeErr := proxyConn.Close(); closeErr != nil {
						return nil, fmt.Errorf("proxy CONNECT failed: %s, close error: %v", resp, closeErr)
					}
					return nil, fmt.Errorf("proxy CONNECT failed: %s", resp)
				}

				c.logger.Debug("proxy CONNECT request successful",
					slog.String("proxy_addr", proxyAddr),
					slog.String("host_port", hostPort),
				)

				for {
					line, err := br.ReadString('\n')
					if err != nil {
						if closeErr := proxyConn.Close(); closeErr != nil {
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
