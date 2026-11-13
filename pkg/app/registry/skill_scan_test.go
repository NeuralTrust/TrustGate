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

package registry_test

import (
	"context"
	"errors"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func scanning(t *testing.T, texts []string, scans []appregistry.SkillScan, err error) *appmocks.SkillScanner {
	t.Helper()
	scanner := appmocks.NewSkillScanner(t)
	scanner.EXPECT().ScanIndirectPromptInjection(mock.Anything, mock.Anything, texts).Return(scans, err).Once()
	return scanner
}

func TestAgentCardRefreshScansTheNewCardsSkills(t *testing.T) {
	t.Parallel()
	reg := pinnedA2ARegistry(t)
	scanner := scanning(t, []string{"Refund"}, []appregistry.SkillScan{{Flagged: true, Score: 0.97}}, nil)
	refresh := appregistry.NewRefreshAgentCard(storedAgent(t, reg),
		appregistry.WithAgentCards(liveCard(t, cardNewSkill), anonymousCards(t)), appregistry.WithSkillScanner(scanner))

	got, err := refresh.Refresh(context.Background(), reg.GatewayID, reg.ID)
	require.NoError(t, err)
	assert.Equal(t, []domain.SkillVerdict{{SkillID: "refund_invoice", Flagged: true, Score: 0.97}}, got.FetchedSkillScan)
}

func TestAgentCardRefreshOfAFailedScanHasNoVerdicts(t *testing.T) {
	t.Parallel()
	reg := pinnedA2ARegistry(t)
	scanner := scanning(t, []string{"Refund"}, nil, errors.New("trustguard scan: status 503"))
	refresh := appregistry.NewRefreshAgentCard(storedAgent(t, reg),
		appregistry.WithAgentCards(liveCard(t, cardNewSkill), anonymousCards(t)), appregistry.WithSkillScanner(scanner))

	got, err := refresh.Refresh(context.Background(), reg.GatewayID, reg.ID)
	require.NoError(t, err)
	assert.True(t, got.Changed)
	assert.Nil(t, got.FetchedSkillScan)
}

func TestAgentCardApprovePinsTheSkillsVerdicts(t *testing.T) {
	t.Parallel()
	reg := pinnedA2ARegistry(t)
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, reg.ID).Return(reg, nil)
	want := []domain.SkillVerdict{{SkillID: "refund_invoice", Score: 0.02}}
	pinner := appmocks.NewA2ACardPinner(t)
	pinner.EXPECT().PinA2ACard(mock.Anything, reg.GatewayID, reg.ID, reg.A2ATarget.CardDigest, mock.MatchedBy(func(next *domain.A2ATarget) bool {
		return assert.ObjectsAreEqual(want, next.SkillScan)
	}), mock.Anything).Return(true, nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()
	scanner := scanning(t, []string{"Refund"}, []appregistry.SkillScan{{Score: 0.02}}, nil)
	approve := appregistry.NewApproveAgentCard(repo, pinner, newCacheManager(), publisher, newTestLogger(), nil,
		appregistry.WithAgentCards(liveCard(t, cardNewSkill), anonymousCards(t)), appregistry.WithSkillScanner(scanner))

	_, err := approve.Approve(context.Background(), reg.GatewayID, reg.ID, digestOf(t, cardNewSkill))
	require.NoError(t, err)
}
