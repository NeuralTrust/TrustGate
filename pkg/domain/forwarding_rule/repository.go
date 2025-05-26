package forwarding_rule

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	GetRule(ctx context.Context, id uuid.UUID, gatewayID uuid.UUID) (*ForwardingRule, error)
	GetRuleByID(ctx context.Context, id uuid.UUID) (*ForwardingRule, error)
	Create(ctx context.Context, rule *ForwardingRule) error
	ListRules(ctx context.Context, gatewayID uuid.UUID) ([]ForwardingRule, error)
	Update(ctx context.Context, rule *ForwardingRule) error
	Delete(ctx context.Context, id, gatewayID uuid.UUID) error
	UpdateRulesCache(ctx context.Context, gatewayID uuid.UUID, rules []ForwardingRule) error
}
