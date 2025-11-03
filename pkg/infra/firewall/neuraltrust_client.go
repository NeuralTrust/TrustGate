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
	client         httpx.Client
	logger         *logrus.Logger
	circuitBreaker httpx.CircuitBreaker
	bufferPool     sync.Pool
}

func NewNeuralTrustFirewallClient(
	client httpx.Client,
	logger *logrus.Logger,
	circuitBreaker httpx.CircuitBreaker,
) Client {
	if client == nil {
		client = &http.Client{}
	}

	return &NeuralTrustFirewallClient{
		client:         client,
		logger:         logger,
		circuitBreaker: circuitBreaker,
		bufferPool: sync.Pool{
			New: func() any {
				buf := make([]byte, 4096)
				return &buf
			},
		},
	}
}

func (c *NeuralTrustFirewallClient) DetectJailbreak(
	ctx context.Context,
	content Content,
	credentials Credentials,
) ([]JailbreakResponse, error) {
	var result []JailbreakResponse
	var err error

	err = c.circuitBreaker.Execute(func() error {
		result, err = c.executeJailbreakRequest(ctx, content, credentials)
		return err
	})
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			c.logger.WithError(err).Error("jailbreak detection failed (circuit breaker)")
		}
		return nil, err
	}

	return result, nil
}

func (c *NeuralTrustFirewallClient) executeJailbreakRequest(
	ctx context.Context,
	content Content,
	credentials Credentials,
) ([]JailbreakResponse, error) {
	body, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		credentials.BaseURL+jailbreakPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create jailbreak request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", credentials.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			c.logger.WithError(err).Error("failed to call jailbreak firewall")
		}
		return nil, fmt.Errorf("failed to call jailbreak firewall: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.WithField("status_code", resp.StatusCode).Error("jailbreak firewall returned non-200 status")
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

	return jailbreakResp, nil
}

func (c *NeuralTrustFirewallClient) DetectToxicity(
	ctx context.Context,
	content Content,
	credentials Credentials,
) ([]ToxicityResponse, error) {
	var result []ToxicityResponse
	var err error

	err = c.circuitBreaker.Execute(func() error {
		result, err = c.executeToxicityRequest(ctx, content, credentials)
		return err
	})
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			c.logger.WithError(err).Error("toxicity detection failed (circuit breaker)")
		}
		return nil, err
	}

	return result, nil
}

func (c *NeuralTrustFirewallClient) executeToxicityRequest(
	ctx context.Context,
	content Content,
	credentials Credentials,
) ([]ToxicityResponse, error) {
	body, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		credentials.BaseURL+toxicityPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create toxicity request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", credentials.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return nil, context.Canceled
		}
		c.logger.WithError(err).WithField("error_type", fmt.Sprintf("%T", err)).Error("failed to call toxicity firewall")
		return nil, fmt.Errorf("failed to call toxicity firewall: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.WithField("status_code", resp.StatusCode).Error("toxicity firewall returned non-200 status")
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

	return toxicityResp, nil
}
