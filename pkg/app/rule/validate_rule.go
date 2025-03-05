package rule

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type ValidateRule struct {
	validatePlugin *plugin.ValidatePlugin
}

func NewValidateRule(validatePlugin *plugin.ValidatePlugin) *ValidateRule {
	return &ValidateRule{
		validatePlugin: validatePlugin,
	}
}

func (s *ValidateRule) Validate(rule *types.CreateRuleRequest) error {

	if rule.Path == "" {
		return fmt.Errorf("path is required")
	}

	if len(rule.Methods) == 0 {
		return fmt.Errorf("at least one method is required")
	}

	if rule.ServiceID == "" {
		return fmt.Errorf("service_id is required")
	}

	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
	}
	for _, method := range rule.Methods {
		if !validMethods[strings.ToUpper(method)] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	if len(rule.PluginChain) > 0 {
		for i, pl := range rule.PluginChain {
			if err := s.validatePlugin.Validate(pl); err != nil {
				return fmt.Errorf("plugin %d: %v", i, err)
			}
		}
	}

	return nil
}
