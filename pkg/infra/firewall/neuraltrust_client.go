package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/sirupsen/logrus"
)

const (
	jailbreakPath = "/v1/jailbreak"
	toxicityPath  = "/v1/toxicity"
)

var ErrFailedFirewallCall = errors.New("firewall service call failed")

type NeuralTrustFirewallClient struct {
	client     httpx.Client
	logger     *logrus.Logger
	bufferPool sync.Pool
}

func NewNeuralTrustFirewallClient(logger *logrus.Logger, opts ...NeuralTrustFirewallClientOption) Client {
	c := &NeuralTrustFirewallClient{
		client: &http.Client{},
		logger: logger,
		bufferPool: sync.Pool{
			New: func() any {
				buf := make([]byte, 4096)
				return &buf
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *NeuralTrustFirewallClient) DetectJailbreak(
	ctx context.Context,
	content Content,
	credentials Credentials,
) ([]JailbreakResponse, error) {
	return c.executeJailbreakRequest(ctx, content, credentials)
}

func (c *NeuralTrustFirewallClient) executeJailbreakRequest(
	ctx context.Context,
	content Content,
	credentials Credentials,
) ([]JailbreakResponse, error) {
	creds := credentials.NeuralTrustCredentials
	if creds.BaseURL == "" {
		return nil, fmt.Errorf("neuraltrust base url is required")
	}
	if creds.Token == "" {
		return nil, fmt.Errorf("neuraltrust token is required")
	}
	body, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		creds.BaseURL+jailbreakPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create jailbreak request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", creds.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return nil, context.Canceled
		}
		c.logger.WithError(err).WithField("error_type", fmt.Sprintf("%T", err)).Warn("failed to call jailbreak firewall")
		return nil, fmt.Errorf("failed to call jailbreak firewall: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		entry := c.logger.WithField("status_code", resp.StatusCode)
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			entry.WithError(readErr).Error("jailbreak firewall returned non-200 status (failed to read body)")
		} else {
			entry.WithField("response_body", string(bodyBytes)).Error("jailbreak firewall returned non-200 status")
		}

		return nil, fmt.Errorf("%w: status %d", ErrFailedFirewallCall, resp.StatusCode)
	}

	bufPtr, ok := c.bufferPool.Get().(*[]byte)
	if !ok {
		return nil, fmt.Errorf("failed to get buffer from pool")
	}
	defer c.bufferPool.Put(bufPtr)
	buf := *bufPtr

	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("jailbreak response read error: %w", err)
	}

	var jailbreakResp []JailbreakResponse
	if err := json.Unmarshal(buf[:n], &jailbreakResp); err != nil {
		return nil, fmt.Errorf("invalid jailbreak response: %w", err)
	}
	c.logger.Info(fmt.Sprintf("jailbreak response: %v", string(buf[:n])))
	return jailbreakResp, nil
}

func (c *NeuralTrustFirewallClient) DetectToxicity(
	ctx context.Context,
	content Content,
	credentials Credentials,
) ([]ToxicityResponse, error) {
	return c.executeToxicityRequest(ctx, content, credentials)
}

func (c *NeuralTrustFirewallClient) executeToxicityRequest(
	ctx context.Context,
	content Content,
	credentials Credentials,
) ([]ToxicityResponse, error) {
	creds := credentials.NeuralTrustCredentials
	if creds.BaseURL == "" {
		return nil, fmt.Errorf("neuraltrust base url is required")
	}
	if creds.Token == "" {
		return nil, fmt.Errorf("neuraltrust token is required")
	}
	body, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		creds.BaseURL+toxicityPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create toxicity request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", creds.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return nil, context.Canceled
		}
		c.logger.WithError(err).WithField("error_type", fmt.Sprintf("%T", err)).Warn("failed to call toxicity firewall")
		return nil, fmt.Errorf("failed to call toxicity firewall: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		entry := c.logger.WithField("status_code", resp.StatusCode)
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			entry.WithError(readErr).Error("toxicity firewall returned non-200 status (failed to read body)")
		} else {
			entry.WithField("response_body", string(bodyBytes)).Error("toxicity firewall returned non-200 status")
		}

		return nil, fmt.Errorf("%w: status %d", ErrFailedFirewallCall, resp.StatusCode)
	}

	bufPtr, ok := c.bufferPool.Get().(*[]byte)
	if !ok {
		return nil, fmt.Errorf("failed to get buffer from pool")
	}
	defer c.bufferPool.Put(bufPtr)
	buf := *bufPtr

	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("toxicity response read error: %w", err)
	}

	var toxicityResp []ToxicityResponse
	if err := json.Unmarshal(buf[:n], &toxicityResp); err != nil {
		return nil, fmt.Errorf("invalid toxicity response: %w", err)
	}
	c.logger.Info(fmt.Sprintf("toxicity response: %v", string(buf[:n])))
	return toxicityResp, nil
}
