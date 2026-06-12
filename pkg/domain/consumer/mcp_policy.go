package consumer

import "github.com/NeuralTrust/AgentGateway/pkg/domain/ids"

type MCPPolicy struct {
	// No omitempty: a present-but-empty toolkit ([]) means deny-all, while a
	// nil toolkit means allow-all; collapsing them on the wire would silently
	// widen a deny-all consumer to allow-all.
	Toolkit  Toolkit  `json:"toolkit"`
	FailMode FailMode `json:"fail_mode,omitempty"`
}

func (p *MCPPolicy) Validate(known map[ids.RegistryID]struct{}) error {
	if p.FailMode == "" {
		p.FailMode = FailModeClosed
	}
	if err := p.FailMode.Validate(); err != nil {
		return err
	}
	return p.Toolkit.Validate(known)
}
