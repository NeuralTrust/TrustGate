package consumer

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Type string

const (
	TypeLLM Type = "LLM"
	TypeMCP Type = "MCP"
	TypeA2A Type = "A2A"
)

func Types() []Type {
	return []Type{TypeLLM, TypeMCP, TypeA2A}
}

func IsValidType(t Type) bool {
	switch t {
	case TypeLLM, TypeMCP, TypeA2A:
		return true
	}
	return false
}

type Consumer struct {
	ID            uuid.UUID         `json:"id"`
	GatewayID     uuid.UUID         `json:"gateway_id"`
	Name          string            `json:"name"`
	Type          Type              `json:"type"`
	Path          string            `json:"path"`
	Paths         []string          `json:"paths,omitempty"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers,omitempty"`
	StripPath     bool              `json:"strip_path"`
	PreserveHost  bool              `json:"preserve_host"`
	Active        bool              `json:"active"`
	Public        bool              `json:"public"`
	RetryAttempts int               `json:"retry_attempts"`
	BackendIDs    []uuid.UUID       `json:"backend_ids"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type CreateParams struct {
	GatewayID     uuid.UUID
	Name          string
	Type          Type
	Path          string
	Paths         []string
	Methods       []string
	Headers       map[string]string
	StripPath     bool
	PreserveHost  bool
	Active        *bool
	Public        bool
	RetryAttempts int
	BackendIDs    []uuid.UUID
}

func New(params CreateParams) (*Consumer, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("consumer: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	active := true
	if params.Active != nil {
		active = *params.Active
	}
	c := &Consumer{
		ID:            id,
		GatewayID:     params.GatewayID,
		Name:          params.Name,
		Type:          params.Type,
		Path:          params.Path,
		Paths:         params.Paths,
		Methods:       params.Methods,
		Headers:       params.Headers,
		StripPath:     params.StripPath,
		PreserveHost:  params.PreserveHost,
		Active:        active,
		Public:        params.Public,
		RetryAttempts: params.RetryAttempts,
		BackendIDs:    params.BackendIDs,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if c.RetryAttempts == 0 {
		c.RetryAttempts = 1
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func Rehydrate(
	id, gatewayID uuid.UUID,
	name string,
	consumerType Type,
	path string,
	paths []string,
	methods []string,
	headers map[string]string,
	stripPath, preserveHost, active, public bool,
	retryAttempts int,
	backendIDs []uuid.UUID,
	createdAt, updatedAt time.Time,
) *Consumer {
	return &Consumer{
		ID:            id,
		GatewayID:     gatewayID,
		Name:          name,
		Type:          consumerType,
		Path:          path,
		Paths:         paths,
		Methods:       methods,
		Headers:       headers,
		StripPath:     stripPath,
		PreserveHost:  preserveHost,
		Active:        active,
		Public:        public,
		RetryAttempts: retryAttempts,
		BackendIDs:    backendIDs,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}
}

func (c *Consumer) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidName)
	}
	if c.GatewayID == uuid.Nil {
		return ErrInvalidGatewayID
	}
	if c.Type == "" {
		c.Type = TypeLLM
	}
	if !IsValidType(c.Type) {
		return fmt.Errorf("%w: %q", ErrInvalidType, c.Type)
	}
	if strings.TrimSpace(c.Path) == "" {
		return fmt.Errorf("%w: path is required", ErrInvalidPath)
	}
	if len(c.Methods) == 0 {
		c.Methods = []string{"POST"}
	} else {
		for _, m := range c.Methods {
			if strings.TrimSpace(m) == "" {
				return fmt.Errorf("%w: method cannot be empty", ErrInvalidMethods)
			}
		}
	}
	if c.RetryAttempts < 0 {
		return fmt.Errorf("%w: retry_attempts must be >= 0", ErrInvalidRetries)
	}
	if len(c.BackendIDs) == 0 {
		return ErrNoBackends
	}
	seen := make(map[uuid.UUID]struct{}, len(c.BackendIDs))
	for _, id := range c.BackendIDs {
		if id == uuid.Nil {
			return fmt.Errorf("%w: nil uuid", ErrInvalidBackendID)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: duplicate backend %s", ErrInvalidBackendID, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func (c *Consumer) AttachBackend(id uuid.UUID) bool {
	if id == uuid.Nil {
		return false
	}
	for _, existing := range c.BackendIDs {
		if existing == id {
			return false
		}
	}
	c.BackendIDs = append(c.BackendIDs, id)
	return true
}

func (c *Consumer) DetachBackend(id uuid.UUID) bool {
	for i, existing := range c.BackendIDs {
		if existing == id {
			c.BackendIDs = append(c.BackendIDs[:i], c.BackendIDs[i+1:]...)
			return true
		}
	}
	return false
}
