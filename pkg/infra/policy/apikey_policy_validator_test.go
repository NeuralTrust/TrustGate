package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewApiKeyPolicyValidator(t *testing.T) {
	// Arrange
	mockRepo := mocks.NewRepository(t)
	logger := logrus.New()

	// Act
	validator := NewApiKeyPolicyValidator(mockRepo, logger)

	// Assert
	assert.NotNil(t, validator)

	// Type assertion to access private fields for testing
	v, ok := validator.(*apiKeyValidator)
	assert.True(t, ok)
	assert.Equal(t, mockRepo, v.ruleRepository)
	assert.Equal(t, logger, v.logger)
}

func TestApiKeyValidator_Validate_EmptyPolicies(t *testing.T) {
	// Arrange
	mockRepo := mocks.NewRepository(t)
	logger := logrus.New()
	validator := NewApiKeyPolicyValidator(mockRepo, logger)

	ctx := context.Background()
	subject := uuid.New()
	policies := []string{}

	// Act
	err := validator.Validate(ctx, apikey.GatewayType, subject, policies)

	// Assert
	assert.NoError(t, err)
	mockRepo.AssertNotCalled(t, "FindByIds")
}

func TestApiKeyValidator_Validate_InvalidUUIDFormat(t *testing.T) {
	// Arrange
	mockRepo := mocks.NewRepository(t)
	logger := logrus.New()
	validator := NewApiKeyPolicyValidator(mockRepo, logger)

	ctx := context.Background()
	subject := uuid.New()
	policies := []string{"invalid-uuid", "another-invalid-uuid"}

	// Act
	err := validator.Validate(ctx, apikey.GatewayType, subject, policies)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy ID format")
	mockRepo.AssertNotCalled(t, "FindByIds")
}

func TestApiKeyValidator_Validate_RepositoryError(t *testing.T) {
	// Arrange
	mockRepo := mocks.NewRepository(t)
	logger := logrus.New()
	validator := NewApiKeyPolicyValidator(mockRepo, logger)

	ctx := context.Background()
	subject := uuid.New()
	policyID := uuid.New()
	policies := []string{policyID.String()}

	repositoryError := errors.New("database connection failed")
	mockRepo.EXPECT().FindByIds(ctx, []uuid.UUID{policyID}, subject).Return(nil, repositoryError)

	// Act
	err := validator.Validate(ctx, apikey.GatewayType, subject, policies)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to validate policies")
}

func TestApiKeyValidator_Validate_SomePoliciesDoNotExist(t *testing.T) {
	// Arrange
	mockRepo := mocks.NewRepository(t)
	logger := logrus.New()
	validator := NewApiKeyPolicyValidator(mockRepo, logger)

	ctx := context.Background()
	subject := uuid.New()

	existingPolicyID := uuid.New()
	missingPolicyID := uuid.New()
	policies := []string{existingPolicyID.String(), missingPolicyID.String()}

	// Return only one rule (the existing one)
	existingRules := []forwarding_rule.ForwardingRule{
		{ID: existingPolicyID},
	}

	mockRepo.EXPECT().FindByIds(ctx, mock.MatchedBy(func(ids []uuid.UUID) bool {
		return len(ids) == 2 &&
			((ids[0] == existingPolicyID && ids[1] == missingPolicyID) ||
				(ids[0] == missingPolicyID && ids[1] == existingPolicyID))
	}), subject).Return(existingRules, nil)

	// Act
	err := validator.Validate(ctx, apikey.GatewayType, subject, policies)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "some policies do not exist")
	assert.Contains(t, err.Error(), missingPolicyID.String())
}

func TestApiKeyValidator_Validate_AllPoliciesExist(t *testing.T) {
	// Arrange
	mockRepo := mocks.NewRepository(t)
	logger := logrus.New()
	validator := NewApiKeyPolicyValidator(mockRepo, logger)

	ctx := context.Background()
	subject := uuid.New()

	policy1ID := uuid.New()
	policy2ID := uuid.New()
	policies := []string{policy1ID.String(), policy2ID.String()}

	// Return all requested rules
	existingRules := []forwarding_rule.ForwardingRule{
		{ID: policy1ID},
		{ID: policy2ID},
	}

	mockRepo.EXPECT().FindByIds(ctx, mock.MatchedBy(func(ids []uuid.UUID) bool {
		return len(ids) == 2 &&
			((ids[0] == policy1ID && ids[1] == policy2ID) ||
				(ids[0] == policy2ID && ids[1] == policy1ID))
	}), subject).Return(existingRules, nil)

	// Act
	err := validator.Validate(ctx, apikey.GatewayType, subject, policies)

	// Assert
	assert.NoError(t, err)
}

func TestApiKeyValidator_Validate_SinglePolicyExists(t *testing.T) {
	// Arrange
	mockRepo := mocks.NewRepository(t)
	logger := logrus.New()
	validator := NewApiKeyPolicyValidator(mockRepo, logger)

	ctx := context.Background()
	subject := uuid.New()

	policyID := uuid.New()
	policies := []string{policyID.String()}

	existingRules := []forwarding_rule.ForwardingRule{
		{ID: policyID},
	}

	mockRepo.EXPECT().FindByIds(ctx, []uuid.UUID{policyID}, subject).Return(existingRules, nil)

	// Act
	err := validator.Validate(ctx, apikey.GatewayType, subject, policies)

	// Assert
	assert.NoError(t, err)
}

func TestApiKeyValidator_Validate_MultipleMissingPolicies(t *testing.T) {
	// Arrange
	mockRepo := mocks.NewRepository(t)
	logger := logrus.New()
	validator := NewApiKeyPolicyValidator(mockRepo, logger)

	ctx := context.Background()
	subject := uuid.New()

	missing1ID := uuid.New()
	missing2ID := uuid.New()
	missing3ID := uuid.New()
	policies := []string{missing1ID.String(), missing2ID.String(), missing3ID.String()}

	// Return empty slice - none exist
	existingRules := []forwarding_rule.ForwardingRule{}

	mockRepo.EXPECT().FindByIds(ctx, mock.MatchedBy(func(ids []uuid.UUID) bool {
		return len(ids) == 3
	}), subject).Return(existingRules, nil)

	// Act
	err := validator.Validate(ctx, apikey.GatewayType, subject, policies)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "some policies do not exist")
	assert.Contains(t, err.Error(), missing1ID.String())
	assert.Contains(t, err.Error(), missing2ID.String())
	assert.Contains(t, err.Error(), missing3ID.String())
}

func TestApiKeyValidator_Validate_MixedValidAndInvalidUUIDs(t *testing.T) {
	// Arrange
	mockRepo := mocks.NewRepository(t)
	logger := logrus.New()
	validator := NewApiKeyPolicyValidator(mockRepo, logger)

	ctx := context.Background()
	subject := uuid.New()

	validUUID := uuid.New()
	policies := []string{validUUID.String(), "invalid-uuid"}

	// Act
	err := validator.Validate(ctx, apikey.GatewayType, subject, policies)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy ID format")
	mockRepo.AssertNotCalled(t, "FindByIds")
}
