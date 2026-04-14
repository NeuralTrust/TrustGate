package forwarding_rule

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	AgentRuleType    Type = "agent"
	EndpointRuleType Type = "endpoint"
)

type Type string

type ForwardingRule struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Name          string
	GatewayID     uuid.UUID              `gorm:"type:uuid;not null"`
	ServiceID     uuid.UUID              `gorm:"type:uuid;not null"`
	Path          string                 `gorm:"not null"`
	Paths         domain.PathsJSON       `gorm:"type:jsonb"`
	Type          Type                   `gorm:"column:rule_type;type:rule_type;default:'endpoint';not null"`
	Methods       domain.MethodsJSON     `gorm:"type:jsonb"`
	Headers       domain.HeadersJSON     `gorm:"type:jsonb"`
	StripPath     bool                   `gorm:"default:false"`
	PreserveHost  bool                   `gorm:"default:false"`
	PluginChain   domain.PluginChainJSON `gorm:"type:jsonb"`
	Active        bool                   `gorm:"default:true"`
	Public        bool                   `gorm:"default:false"`
	RetryAttempts int                    `gorm:"default:1"`
	TrustLens     *domain.TrustLensJSON  `gorm:"type:jsonb"`
	SessionConfig *SessionConfig         `json:"session_config,omitempty" gorm:"type:jsonb"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type SessionConfig struct {
	HeaderName    string `json:"header_name"`
	BodyParamName string `json:"body_param_name"`
}

func (t SessionConfig) Value() (driver.Value, error) {
	return json.Marshal(t)
}

func (t *SessionConfig) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("could not convert value %v to []byte", value)
	}
	return json.Unmarshal(bytes, t)
}

func (r *ForwardingRule) AllPaths() []string {
	if len(r.Paths) > 0 {
		return r.Paths
	}
	return []string{r.Path}
}

func (r *ForwardingRule) Validate() error {
	if r.Path == "" {
		return fmt.Errorf("path is required")
	}

	if len(r.Paths) > 0 {
		for i, p := range r.Paths {
			if p == "" {
				return fmt.Errorf("paths[%d] must not be empty", i)
			}
		}
	}

	for _, p := range r.AllPaths() {
		if err := validateWildcard(p); err != nil {
			return err
		}
	}

	if r.ServiceID == uuid.Nil {
		return fmt.Errorf("service_id is required")
	}

	if len(r.Methods) == 0 {
		return fmt.Errorf("at least one HTTP method is required")
	}

	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true,
	}

	for _, method := range r.Methods {
		if !validMethods[method] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	if r.SessionConfig != nil {
		if r.SessionConfig.HeaderName != "" && r.SessionConfig.BodyParamName != "" {
			return fmt.Errorf("session_config: header_name and body_param_name are mutually exclusive")
		}
		if r.SessionConfig.HeaderName == "" && r.SessionConfig.BodyParamName == "" {
			r.SessionConfig.HeaderName = "X-TG-SESSION-ID"
		}
	}

	return nil
}

// BeforeCreate is called before inserting a new forwarding rule into the database
func (r *ForwardingRule) BeforeCreate(tx *gorm.DB) error {
	// Generate UUID if not set
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}

	// Set timestamps
	now := time.Now()
	r.CreatedAt = now
	r.UpdatedAt = now

	// Set default rule type if not provided
	if r.Type == "" {
		r.Type = EndpointRuleType
	}

	// Generate unique IDs for plugins in the chain
	if r.PluginChain != nil {
		for i := range r.PluginChain {
			if r.PluginChain[i].ID == "" { // Only generate if ID is not already set
				r.PluginChain[i].ID = uuid.New().String()
			}
		}
	}
	return r.Validate()
}

func (r *ForwardingRule) BeforeUpdate(tx *gorm.DB) error {
	r.UpdatedAt = time.Now()
	return r.Validate()
}

func (r *ForwardingRule) TableName() string {
	return "forwarding_rules"
}

func validateWildcard(path string) error {
	if !strings.Contains(path, "*") {
		return nil
	}
	if strings.Count(path, "*") > 1 {
		return fmt.Errorf("only one wildcard (*) is allowed per path")
	}
	if !strings.HasSuffix(path, "/*") {
		return fmt.Errorf("wildcard (*) is only allowed at the end of a path (e.g. /v1/*)")
	}
	return nil
}
