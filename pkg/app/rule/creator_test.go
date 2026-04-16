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
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	serviceMocks "github.com/NeuralTrust/TrustGate/pkg/domain/service/mocks"
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

func setupRuleCreator(t *testing.T) (
	rule.Creator,
	*frMocks.Repository,
	*gatewayMocks.Repository,
	*serviceMocks.Repository,
	*pluginMocks.ValidatePluginChain,
	*cacheMocks.EventPublisher,
	*ruleMocks.Matcher,
) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	repo := frMocks.NewRepository(t)
	gatewayRepo := gatewayMocks.NewRepository(t)
	serviceRepo := serviceMocks.NewRepository(t)
	chainValidator := pluginMocks.NewValidatePluginChain(t)
	publisher := cacheMocks.NewEventPublisher(t)
	matcher := ruleMocks.NewMatcher(t)

	c := rule.NewCreator(logger, repo, gatewayRepo, serviceRepo, chainValidator, publisher, matcher)
	return c, repo, gatewayRepo, serviceRepo, chainValidator, publisher, matcher
}

func validCreateRuleRequest() *request.CreateRuleRequest {
	serviceID := uuid.New().String()
	return &request.CreateRuleRequest{
		Name:      "test-rule",
		Path:      types.FlexiblePath{Primary: "/api/v1"},
		Methods:   []string{"GET", "POST"},
		ServiceID: serviceID,
	}
}

func TestCreator_Create_Success(t *testing.T) {
	c, repo, gatewayRepo, serviceRepo, _, publisher, _ := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	serviceRepo.EXPECT().Get(ctx, req.ServiceID).Return(&domainService.Service{}, nil)
	repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	repo.EXPECT().Create(ctx, mock.AnythingOfType("*forwarding_rule.ForwardingRule")).Return(nil)
	publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)

	result, err := c.Create(ctx, gatewayID, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-rule", result.Name)
	assert.Equal(t, "/api/v1", result.Path)
	assert.Equal(t, domain.MethodsJSON{"GET", "POST"}, result.Methods)
	assert.True(t, result.Active)
	assert.False(t, result.Public)
	assert.Equal(t, forwarding_rule.EndpointRuleType, result.Type)
}

func TestCreator_Create_InvalidServiceID(t *testing.T) {
	c, _, _, _, _, _, _ := setupRuleCreator(t)
	ctx := context.Background()

	req := validCreateRuleRequest()
	req.ServiceID = "not-a-uuid"

	result, err := c.Create(ctx, uuid.New(), req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrValidation)
}

func TestCreator_Create_GatewayNotFound(t *testing.T) {
	c, _, gatewayRepo, _, _, _, _ := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(nil, errors.New("not found"))

	result, err := c.Create(ctx, gatewayID, validCreateRuleRequest())

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrGatewayNotFound)
}

func TestCreator_Create_ServiceNotFound(t *testing.T) {
	c, _, gatewayRepo, serviceRepo, _, _, _ := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	serviceRepo.EXPECT().Get(ctx, req.ServiceID).Return(nil, errors.New("not found"))

	result, err := c.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrServiceNotFound)
}

func TestCreator_Create_DuplicatePath(t *testing.T) {
	c, repo, gatewayRepo, serviceRepo, _, _, matcher := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()

	existing := forwarding_rule.ForwardingRule{
		ID:        uuid.New(),
		GatewayID: gatewayID,
		Path:      "/api/v1",
	}

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	serviceRepo.EXPECT().Get(ctx, req.ServiceID).Return(&domainService.Service{}, nil)
	repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{existing}, nil)
	matcher.EXPECT().NormalizePath("/api/v1").Return("/api/v1")

	result, err := c.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrRuleAlreadyExists)
}

func TestCreator_Create_RepositoryError(t *testing.T) {
	c, repo, gatewayRepo, serviceRepo, _, _, _ := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	serviceRepo.EXPECT().Get(ctx, req.ServiceID).Return(&domainService.Service{}, nil)
	repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	repo.EXPECT().Create(ctx, mock.Anything).Return(errors.New("db error"))

	result, err := c.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to create rule")
}

func TestCreator_Create_WithPluginChain(t *testing.T) {
	c, repo, gatewayRepo, serviceRepo, chainValidator, publisher, _ := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	req.PluginChain = []pluginTypes.PluginConfig{
		{ID: uuid.New().String(), Name: "rate_limiter", Stage: "pre_request", Priority: 1, Settings: map[string]interface{}{}},
	}

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	serviceRepo.EXPECT().Get(ctx, req.ServiceID).Return(&domainService.Service{}, nil)
	chainValidator.EXPECT().Validate(ctx, gatewayID, req.PluginChain).Return(nil)
	repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	repo.EXPECT().Create(ctx, mock.Anything).Return(nil)
	publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)

	result, err := c.Create(ctx, gatewayID, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.PluginChain, 1)
}

func TestCreator_Create_PluginChainValidationFails(t *testing.T) {
	c, _, gatewayRepo, serviceRepo, chainValidator, _, _ := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	req.PluginChain = []pluginTypes.PluginConfig{
		{ID: uuid.New().String(), Name: "invalid_plugin", Stage: "pre_request", Priority: 1, Settings: map[string]interface{}{}},
	}

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	serviceRepo.EXPECT().Get(ctx, req.ServiceID).Return(&domainService.Service{}, nil)
	chainValidator.EXPECT().Validate(ctx, gatewayID, req.PluginChain).Return(errors.New("plugin not found"))

	result, err := c.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrValidation)
}

func TestCreator_Create_AgentType(t *testing.T) {
	c, repo, gatewayRepo, serviceRepo, _, publisher, _ := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()
	agentType := "agent"
	req.Type = &agentType

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	serviceRepo.EXPECT().Get(ctx, req.ServiceID).Return(&domainService.Service{}, nil)
	repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	repo.EXPECT().Create(ctx, mock.Anything).Return(nil)
	publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)

	result, err := c.Create(ctx, gatewayID, req)

	require.NoError(t, err)
	assert.Equal(t, forwarding_rule.AgentRuleType, result.Type)
}

func TestCreator_Create_PublishFails_StillReturns(t *testing.T) {
	c, repo, gatewayRepo, serviceRepo, _, publisher, _ := setupRuleCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	req := validCreateRuleRequest()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	serviceRepo.EXPECT().Get(ctx, req.ServiceID).Return(&domainService.Service{}, nil)
	repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	repo.EXPECT().Create(ctx, mock.Anything).Return(nil)
	publisher.EXPECT().Publish(ctx, mock.Anything).Return(errors.New("publish error"))

	result, err := c.Create(ctx, gatewayID, req)

	require.NoError(t, err)
	assert.NotNil(t, result)
}
