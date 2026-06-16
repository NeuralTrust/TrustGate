// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth

import (
	"context"
	"errors"
	"net/url"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	vaultdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/vault"
)

func (s *connectService) ChainURL(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, principalSub, resumeURL string) (string, error) {
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return "", err
	}
	rc := s.chainTarget(ctx, data, gatewayID, resource, principalSub)
	if rc == nil {
		return "", nil
	}
	consumerPath := appconsumer.MCPPath(rc.Consumer.Slug)
	id, err := s.mintTicket(ctx, ConnectTicket{
		GatewayID:    gatewayID.String(),
		PrincipalSub: principalSub,
		ConsumerPath: consumerPath,
		ResumeURL:    resumeURL,
	})
	if err != nil {
		return "", err
	}
	return baseURL + consumerPath + "/connect?ticket=" + id, nil
}

func (s *connectService) chainTarget(ctx context.Context, data *appconsumer.Data, gatewayID ids.GatewayID, resource, principalSub string) *appconsumer.RoutableConsumer {
	if resource != "" {
		if res, err := url.Parse(resource); err == nil && res.Path != "" {
			if rc, ok := data.MatchPath(res.Path); ok {
				if s.hasUnlinked(ctx, gatewayID, rc, principalSub) {
					return rc
				}
				return nil
			}
		}
	}
	for i := range data.Consumers {
		rc := &data.Consumers[i]
		if rc.Consumer == nil || !rc.Consumer.Active {
			continue
		}
		if s.hasUnlinked(ctx, gatewayID, rc, principalSub) {
			return rc
		}
	}
	return nil
}

func (s *connectService) hasUnlinked(ctx context.Context, gatewayID ids.GatewayID, rc *appconsumer.RoutableConsumer, principalSub string) bool {
	for _, reg := range rc.Registries {
		cfg := forwardedAuth(reg)
		if cfg == nil {
			continue
		}
		if _, err := s.vault.Find(ctx, gatewayID, principalSub, cfg.Provider); errors.Is(err, vaultdomain.ErrNotFound) {
			return true
		}
	}
	return false
}
