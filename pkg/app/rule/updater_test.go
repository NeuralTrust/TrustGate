package rule_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	appPlugin "github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	ruleMocks "github.com/NeuralTrust/TrustGate/pkg/app/rule/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	frMocks "github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	pluginsMocks "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupRuleUpdater(t *testing.T) (
	rule.Updater,
	*frMocks.Repository,
	*cacheMocks.Client,
	*cacheMocks.EventPublisher,
	*ruleMocks.Matcher,
	*pluginsMocks.Manager,
) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	repo := frMocks.NewRepository(t)
	cache := cacheMocks.NewClient(t)
	publisher := cacheMocks.NewEventPublisher(t)
	matcher := ruleMocks.NewMatcher(t)
	pluginManager := pluginsMocks.NewManager(t)

	validatePlugin := appPlugin.NewValidatePlugin(pluginManager)
	u := rule.NewUpdater(logger, repo, cache, validatePlugin, publisher, matcher)
	return u, repo, cache, publisher, matcher, pluginManager
}

func cachedRulesJSON(t *testing.T, rules []types.ForwardingRuleDTO) string {
	b, err := json.Marshal(rules)
	require.NoError(t, err)
	return string(b)
}

func TestUpdater_Update_Success(t *testing.T) {
	u, repo, cache, publisher, _, _ := setupRuleUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	ruleID := uuid.New()
	serviceID := uuid.New()

	existing := &forwarding_rule.ForwardingRule{
		ID:        ruleID,
		GatewayID: gatewayID,
		ServiceID: serviceID,
		Name:      "old-name",
		Path:      "/api/v1",
		Methods:   []string{"GET"},
	}

	req := &request.UpdateRuleRequest{
		Name: "new-name",
	}

	repo.EXPECT().GetRule(ctx, ruleID, gatewayID).Return(existing, nil)
	repo.EXPECT().Update(ctx, mock.AnythingOfType("*forwarding_rule.ForwardingRule")).Return(nil)

	cachedRules := cachedRulesJSON(t, []types.ForwardingRuleDTO{
		{ID: ruleID.String(), Name: "old-name", Path: "/api/v1"},
	})
	cache.EXPECT().Get(ctx, "rules:"+gatewayID.String()).Return(cachedRules, nil)
	cache.EXPECT().Set(ctx, "rules:"+gatewayID.String(), mock.Anything, mock.Anything).Return(nil)
	publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)

	err := u.Update(ctx, gatewayID, ruleID, req)

	require.NoError(t, err)
}

func TestUpdater_Update_RuleNotFound(t *testing.T) {
	u, repo, _, _, _, _ := setupRuleUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	ruleID := uuid.New()

	repo.EXPECT().GetRule(ctx, ruleID, gatewayID).Return(nil, errors.New("not found"))

	err := u.Update(ctx, gatewayID, ruleID, &request.UpdateRuleRequest{Name: "new"})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get rule")
}

func TestUpdater_Update_RuleNotFoundNil(t *testing.T) {
	u, repo, _, _, _, _ := setupRuleUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	ruleID := uuid.New()

	repo.EXPECT().GetRule(ctx, ruleID, gatewayID).Return(nil, nil)

	err := u.Update(ctx, gatewayID, ruleID, &request.UpdateRuleRequest{Name: "new"})

	assert.Error(t, err)
	assert.True(t, domain.IsNotFoundError(err))
}

func TestUpdater_Update_InvalidServiceID(t *testing.T) {
	u, repo, _, _, _, _ := setupRuleUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	ruleID := uuid.New()

	existing := &forwarding_rule.ForwardingRule{
		ID:        ruleID,
		GatewayID: gatewayID,
		ServiceID: uuid.New(),
	}

	repo.EXPECT().GetRule(ctx, ruleID, gatewayID).Return(existing, nil)

	err := u.Update(ctx, gatewayID, ruleID, &request.UpdateRuleRequest{ServiceID: "not-a-uuid"})

	assert.ErrorIs(t, err, domain.ErrValidation)
}

func TestUpdater_Update_PathUniquenessViolation(t *testing.T) {
	u, repo, _, _, matcher, _ := setupRuleUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	ruleID := uuid.New()
	serviceID := uuid.New()
	otherRuleID := uuid.New()

	existing := &forwarding_rule.ForwardingRule{
		ID:        ruleID,
		GatewayID: gatewayID,
		ServiceID: serviceID,
	}

	otherRule := forwarding_rule.ForwardingRule{
		ID:        otherRuleID,
		GatewayID: gatewayID,
		ServiceID: serviceID,
		Path:      "/api/v2",
	}

	repo.EXPECT().GetRule(ctx, ruleID, gatewayID).Return(existing, nil)
	repo.EXPECT().ListRules(ctx, gatewayID).Return([]forwarding_rule.ForwardingRule{otherRule}, nil)
	matcher.EXPECT().NormalizePath("/api/v2").Return("/api/v2")

	err := u.Update(ctx, gatewayID, ruleID, &request.UpdateRuleRequest{
		ServiceID: serviceID.String(),
		Path:      &types.FlexiblePath{Primary: "/api/v2"},
	})

	assert.ErrorIs(t, err, domain.ErrRuleAlreadyExists)
}

func TestUpdater_Update_RepositoryError(t *testing.T) {
	u, repo, _, _, _, _ := setupRuleUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	ruleID := uuid.New()

	existing := &forwarding_rule.ForwardingRule{
		ID:        ruleID,
		GatewayID: gatewayID,
		ServiceID: uuid.New(),
	}

	repo.EXPECT().GetRule(ctx, ruleID, gatewayID).Return(existing, nil)
	repo.EXPECT().Update(ctx, mock.Anything).Return(errors.New("db error"))

	err := u.Update(ctx, gatewayID, ruleID, &request.UpdateRuleRequest{Name: "new"})

	assert.Contains(t, err.Error(), "failed to update rule")
}

func TestUpdater_Update_AppliesFieldsCorrectly(t *testing.T) {
	u, repo, cache, publisher, _, _ := setupRuleUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	ruleID := uuid.New()

	existing := &forwarding_rule.ForwardingRule{
		ID:        ruleID,
		GatewayID: gatewayID,
		ServiceID: uuid.New(),
		Name:      "old",
		Path:      "/old",
		Methods:   []string{"GET"},
		Active:    true,
	}

	stripPath := true
	active := false
	retryAttempts := 5

	req := &request.UpdateRuleRequest{
		Name:          "updated",
		Methods:       []string{"POST", "PUT"},
		StripPath:     &stripPath,
		Active:        &active,
		RetryAttempts: &retryAttempts,
	}

	repo.EXPECT().GetRule(ctx, ruleID, gatewayID).Return(existing, nil)
	repo.EXPECT().Update(ctx, mock.MatchedBy(func(rule *forwarding_rule.ForwardingRule) bool {
		return rule.Name == "updated" &&
			len(rule.Methods) == 2 &&
			rule.StripPath == true &&
			rule.Active == false &&
			rule.RetryAttempts == 5
	})).Return(nil)

	cachedRules := cachedRulesJSON(t, []types.ForwardingRuleDTO{
		{ID: ruleID.String(), Name: "old", Path: "/old"},
	})
	cache.EXPECT().Get(ctx, mock.Anything).Return(cachedRules, nil)
	cache.EXPECT().Set(ctx, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)

	err := u.Update(ctx, gatewayID, ruleID, req)

	require.NoError(t, err)
}
