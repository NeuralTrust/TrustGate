package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	appUpstream "github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	appUpstreamMocks "github.com/NeuralTrust/TrustGate/pkg/app/upstream/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/gcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func buildMockCache(t *testing.T) cache.Client {
	c := cacheMocks.NewClient(t)
	c.EXPECT().SaveUpstream(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	return c
}

func newFiber() *fiber.App { return fiber.New() }

func buildTestUpdater(t *testing.T, repo upstream.Repository, cacheInstance cache.Client) appUpstream.Updater {
	logger := logrus.New()
	saService := gcp.NewServiceAccountService(nil)
	pub := cacheMocks.NewEventPublisher(t)
	pub.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Maybe()
	desc := appUpstreamMocks.NewDescriptionEmbeddingCreator(t)
	desc.EXPECT().Process(mock.Anything, mock.Anything).Return(nil).Maybe()
	return appUpstream.NewUpdater(
		logger,
		repo,
		pub,
		cacheInstance,
		desc,
		saService,
	)
}

func TestUpdateUpstream_OAuthValidation_ClientCredentialsMissingClientID(t *testing.T) {
	repo := new(mocks.Repository)
	cacheInstance := buildMockCache(t)
	logger := logrus.New()
	updater := buildTestUpdater(t, repo, cacheInstance)
	h := NewUpdateUpstreamHandler(logger, updater, nil)

	app := newFiber()
	app.Put("/api/v1/gateways/:gateway_id/upstreams/:upstream_id", h.Handle)

	gatewayID := uuid.New()
	upID := uuid.New()
	existing := &upstream.Upstream{ID: upID, GatewayID: gatewayID, Name: "u1", Algorithm: "round-robin", Targets: upstream.Targets{}}
	repo.EXPECT().GetUpstream(mock.Anything, upID).Return(existing, nil)
	repo.EXPECT().UpdateUpstream(mock.Anything, mock.Anything).Return(nil)

	body := map[string]interface{}{
		"name":      "u1",
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "api",
				"port":     443,
				"protocol": "https",
				"auth": map[string]interface{}{
					"type": "oauth2",
					"oauth": map[string]interface{}{
						"token_url":      "https://auth/token",
						"grant_type":     "client_credentials",
						"use_basic_auth": false,
					},
				},
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/gateways/%s/upstreams/%s", gatewayID, upID), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestUpdateUpstream_Success_Minimal(t *testing.T) {
	repo := new(mocks.Repository)
	cacheInstance := buildMockCache(t)
	logger := logrus.New()
	updater := buildTestUpdater(t, repo, cacheInstance)
	h := NewUpdateUpstreamHandler(logger, updater, nil)

	app := newFiber()
	app.Put("/api/v1/gateways/:gateway_id/upstreams/:upstream_id", h.Handle)

	gatewayID := uuid.New()
	upID := uuid.New()
	existing := &upstream.Upstream{ID: upID, GatewayID: gatewayID, Name: "u1", Algorithm: "round-robin", Targets: upstream.Targets{}}
	repo.EXPECT().GetUpstream(mock.Anything, upID).Return(existing, nil)
	repo.EXPECT().UpdateUpstream(mock.Anything, mock.Anything).Return(nil)

	body := map[string]interface{}{
		"name":      "u1",
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "api",
				"port":     443,
				"protocol": "https",
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/gateways/%s/upstreams/%s", gatewayID, upID), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}
