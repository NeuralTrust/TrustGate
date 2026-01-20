package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/sirupsen/logrus"
)

const (
	jailbreakPath  = "/v1/jailbreak"
	toxicityPath   = "/v1/toxicity"
	moderationPath = "/v1/prompt-moderation"
)

var ErrFailedFirewallCall = errors.New("firewall service call failed")

type NeuralTrustFirewallClient struct {
	client httpx.Client
	logger *logrus.Logger
}

func NewNeuralTrustFirewallClient(logger *logrus.Logger, opts ...NeuralTrustFirewallClientOption) Client {
	c := &NeuralTrustFirewallClient{
		client: &http.Client{},
		logger: logger,
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
	var result []JailbreakResponse
	if err := c.doRequest(ctx, jailbreakPath, content, credentials, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *NeuralTrustFirewallClient) DetectToxicity(
	ctx context.Context,
	content Content,
	credentials Credentials,
) ([]ToxicityResponse, error) {
	var result []ToxicityResponse
	if err := c.doRequest(ctx, toxicityPath, content, credentials, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *NeuralTrustFirewallClient) DetectModeration(
	ctx context.Context,
	content ModerationContent,
	credentials Credentials,
) ([]ModerationResponse, error) {
	var result []ModerationResponse
	if err := c.doRequest(ctx, moderationPath, content, credentials, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *NeuralTrustFirewallClient) doRequest(
	ctx context.Context,
	path string,
	payload any,
	credentials Credentials,
	result any,
) error {
	creds := credentials.NeuralTrustCredentials
	if creds.BaseURL == "" {
		return errors.New("neuraltrust base url is required")
	}
	if creds.Token == "" {
		return errors.New("neuraltrust token is required")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, creds.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", creds.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		if context.Cause(ctx) != nil {
			return context.Canceled
		}
		c.logger.WithError(err).WithField("path", path).Warn("firewall request failed")
		return fmt.Errorf("firewall request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		c.logger.WithFields(logrus.Fields{
			"status_code":   resp.StatusCode,
			"path":          path,
			"response_body": string(respBody),
		}).Error("firewall returned non-200 status")
		return fmt.Errorf("%w: status %d", ErrFailedFirewallCall, resp.StatusCode)
	}

	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"path":     path,
		"response": string(respBody),
	}).Debug("firewall response")

	return nil
}
