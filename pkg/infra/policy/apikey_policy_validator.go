package policy

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type apiKeyValidator struct {
	ruleRepository forwarding_rule.Repository
	logger         *logrus.Logger
}

func NewApiKeyPolicyValidator(
	ruleRepository forwarding_rule.Repository,
	logger *logrus.Logger,
) apikey.PolicyValidator {
	return &apiKeyValidator{
		ruleRepository: ruleRepository,
		logger:         logger,
	}
}

func (s *apiKeyValidator) Validate(
	ctx context.Context,
	subjectType apikey.SubjectType,
	subject *uuid.UUID,
	policies []string,
) error {
	if len(policies) == 0 {
		return nil
	}
	if subjectType != apikey.GatewayType {
		return fmt.Errorf("invalid subject type: %s", subjectType)
	}
	policyUUIDs := make([]uuid.UUID, 0, len(policies))
	for _, policyID := range policies {
		policyUUID, err := uuid.Parse(policyID)
		if err != nil {
			s.logger.WithError(err).WithField("policy_id", policyID).Error("invalid policy ID format")
			return apikey.ErrInvalidPolicyIDFormat
		}
		policyUUIDs = append(policyUUIDs, policyUUID)
	}

	if subject == nil {
		return apikey.ErrSubjectRequired
	}

	existingRules, err := s.ruleRepository.FindByIds(ctx, policyUUIDs, *subject)
	if err != nil {
		s.logger.WithError(err).Error("failed to validate policies")
		return apikey.ErrFailedToValidatePolicy
	}

	if len(existingRules) != len(policyUUIDs) {
		existingIDs := make(map[uuid.UUID]bool)
		for _, rule := range existingRules {
			existingIDs[rule.ID] = true
		}

		var missingPolicies []uuid.UUID
		for _, policyUUID := range policyUUIDs {
			if !existingIDs[policyUUID] {
				missingPolicies = append(missingPolicies, policyUUID)
			}
		}

		return &apikey.MissingPoliciesError{Missing: missingPolicies}
	}
	return nil
}
