package rule_test

import (
	"context"
	"errors"
	"testing"

	pluginMocks "github.com/NeuralTrust/TrustGate/pkg/app/plugin/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	ruleMocks "github.com/NeuralTrust/TrustGate/pkg/app/rule/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	frMocks "github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule/mocks"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewayMocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	upstreamMocks "github.com/NeuralTrust/TrustGate/pkg/domain/upstream/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type ruleCreatorFixture struct {
	creator        rule.Creator
	repo           *frMocks.Repository
	gatewayRepo    *gatewayMocks.Repository
	upstreamRepo   *upstreamMocks.Repository
	chainValidator *pluginMocks.ValidatePluginChain
	publisher      *cacheMocks.EventPublisher
	matcher        *ruleMocks.Matcher
}

func setupRuleCreator(t *testing.T) ruleCreatorFixture {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	f := ruleCreatorFixture{
		repo:           frMocks.NewRepository(t),
		gatewayRepo:    gatewayMocks.NewRepository(t),
		upstreamRepo:   upstreamMocks.NewRepository(t),
		chainValidator: pluginMocks.NewValidatePluginChain(t),
		publisher:      cacheMocks.NewEventPublisher(t),
		matcher:        ruleMocks.NewMatcher(t),
	}

	f.creator = rule.NewCreator(
		logger,
		f.repo,
		f.gatewayRepo,
		f.upstreamRepo,
		f.chainValidator,
		f.publisher,
		f.matcher,
	)
	return f
}

func validCreateRuleRequest() *request.CreateRuleRequest {
	return &request.CreateRuleRequest{
		Name:       "test-rule",
		Path:       types.FlexiblePath{Primary: "/api/v1"},
		Methods:    []string{"GET", "POST"},
		UpstreamID: uuid.New().String(),
	}
}

func TestCreator_Create_Success(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	upstreamUUID := uuid.MustParse(req.UpstreamID)

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	f.upstreamRepo.EXPECT().GetUpstream(ctx, upstreamUUID).
		Return(&domainUpstream.Upstream{ID: upstreamUUID, GatewayID: gatewayID}, nil)
	f.repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	f.repo.EXPECT().Create(ctx, mock.AnythingOfType("*forwarding_rule.ForwardingRule")).Return(nil)
	f.publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)

	result, err := f.creator.Create(ctx, gatewayID, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-rule", result.Name)
	assert.Equal(t, "/api/v1", result.Path)
	assert.Equal(t, domain.MethodsJSON{"GET", "POST"}, result.Methods)
	assert.Equal(t, upstreamUUID, result.UpstreamID)
	assert.True(t, result.Active)
	assert.False(t, result.Public)
	assert.Equal(t, forwarding_rule.EndpointRuleType, result.Type)
}

func TestCreator_Create_InvalidUpstreamID(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()

	req := validCreateRuleRequest()
	req.UpstreamID = "not-a-uuid"

	result, err := f.creator.Create(ctx, uuid.New(), req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrValidation)
}

func TestCreator_Create_GatewayNotFound(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(nil, errors.New("not found"))

	result, err := f.creator.Create(ctx, gatewayID, validCreateRuleRequest())

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrGatewayNotFound)
}

func TestCreator_Create_UpstreamNotFound(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	upstreamUUID := uuid.MustParse(req.UpstreamID)

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	f.upstreamRepo.EXPECT().GetUpstream(ctx, upstreamUUID).Return(nil, errors.New("not found"))

	result, err := f.creator.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrUpstreamNotFound)
}

// Verifies cross-gateway protection: an upstream owned by a different gateway
// must surface as ErrUpstreamNotFound (no information leak about existence).
func TestCreator_Create_UpstreamFromOtherGateway(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	otherGatewayID := uuid.New()
	req := validCreateRuleRequest()
	upstreamUUID := uuid.MustParse(req.UpstreamID)

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	f.upstreamRepo.EXPECT().GetUpstream(ctx, upstreamUUID).
		Return(&domainUpstream.Upstream{ID: upstreamUUID, GatewayID: otherGatewayID}, nil)

	result, err := f.creator.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrUpstreamNotFound)
}

func TestCreator_Create_DuplicatePath(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	upstreamUUID := uuid.MustParse(req.UpstreamID)

	existing := forwarding_rule.ForwardingRule{
		ID:        uuid.New(),
		GatewayID: gatewayID,
		Path:      "/api/v1",
	}

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	f.upstreamRepo.EXPECT().GetUpstream(ctx, upstreamUUID).
		Return(&domainUpstream.Upstream{ID: upstreamUUID, GatewayID: gatewayID}, nil)
	f.repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{existing}, nil)
	f.matcher.EXPECT().NormalizePath("/api/v1").Return("/api/v1")

	result, err := f.creator.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrRuleAlreadyExists)
}

func TestCreator_Create_RepositoryError(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	upstreamUUID := uuid.MustParse(req.UpstreamID)

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	f.upstreamRepo.EXPECT().GetUpstream(ctx, upstreamUUID).
		Return(&domainUpstream.Upstream{ID: upstreamUUID, GatewayID: gatewayID}, nil)
	f.repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	f.repo.EXPECT().Create(ctx, mock.Anything).Return(errors.New("db error"))

	result, err := f.creator.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to create rule")
}

func TestCreator_Create_WithPluginChain(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	upstreamUUID := uuid.MustParse(req.UpstreamID)
	req.PluginChain = []pluginTypes.PluginConfig{
		{ID: uuid.New().String(), Name: "rate_limiter", Stage: "pre_request", Priority: 1, Settings: map[string]interface{}{}},
	}

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	f.upstreamRepo.EXPECT().GetUpstream(ctx, upstreamUUID).
		Return(&domainUpstream.Upstream{ID: upstreamUUID, GatewayID: gatewayID}, nil)
	f.chainValidator.EXPECT().Validate(ctx, gatewayID, req.PluginChain).Return(nil)
	f.repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	f.repo.EXPECT().Create(ctx, mock.Anything).Return(nil)
	f.publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)

	result, err := f.creator.Create(ctx, gatewayID, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.PluginChain, 1)
}

func TestCreator_Create_PluginChainValidationFails(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	upstreamUUID := uuid.MustParse(req.UpstreamID)
	req.PluginChain = []pluginTypes.PluginConfig{
		{ID: uuid.New().String(), Name: "invalid_plugin", Stage: "pre_request", Priority: 1, Settings: map[string]interface{}{}},
	}

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	f.upstreamRepo.EXPECT().GetUpstream(ctx, upstreamUUID).
		Return(&domainUpstream.Upstream{ID: upstreamUUID, GatewayID: gatewayID}, nil)
	f.chainValidator.EXPECT().Validate(ctx, gatewayID, req.PluginChain).Return(errors.New("plugin not found"))

	result, err := f.creator.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrValidation)
}

func TestCreator_Create_AgentType(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	upstreamUUID := uuid.MustParse(req.UpstreamID)
	agentType := "agent"
	req.Type = &agentType

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	f.upstreamRepo.EXPECT().GetUpstream(ctx, upstreamUUID).
		Return(&domainUpstream.Upstream{ID: upstreamUUID, GatewayID: gatewayID}, nil)
	f.repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	f.repo.EXPECT().Create(ctx, mock.Anything).Return(nil)
	f.publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)

	result, err := f.creator.Create(ctx, gatewayID, req)

	require.NoError(t, err)
	assert.Equal(t, forwarding_rule.AgentRuleType, result.Type)
}

func TestCreator_Create_PublishFails_StillReturns(t *testing.T) {
	f := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	upstreamUUID := uuid.MustParse(req.UpstreamID)

	f.gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	f.upstreamRepo.EXPECT().GetUpstream(ctx, upstreamUUID).
		Return(&domainUpstream.Upstream{ID: upstreamUUID, GatewayID: gatewayID}, nil)
	f.repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	f.repo.EXPECT().Create(ctx, mock.Anything).Return(nil)
	f.publisher.EXPECT().Publish(ctx, mock.Anything).Return(errors.New("publish error"))

	result, err := f.creator.Create(ctx, gatewayID, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
}
