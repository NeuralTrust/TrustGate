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

package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

var ErrNoStoreConsumer = fmt.Errorf("store: no consumer admits the request: %w", routingdomain.ErrModelDenied)

var errNoPrimaryCandidate = fmt.Errorf("store: no primary candidate admits the request: %w", routingdomain.ErrModelDenied)

type StoreSelectInput struct {
	Links   []appconsumer.StoreLink
	Data    *appconsumer.Data
	Request *infracontext.RequestContext
}

type StoreSelection struct {
	Link       appconsumer.StoreLink
	Keep       CandidateFilter
	Intent     routingdomain.Intent
	Ref        string
	Candidates *routingdomain.CandidateSet
}

// StoreSelector picks the personal consumer that serves a store request from
// links in the order Data.StoreLinks returns them. A registry without an
// allow-list admits a short model unless its provider's catalog listing omits
// it; with no listing for the provider it admits any short model.
//
//go:generate mockery --name=StoreSelector --dir=. --output=./mocks --filename=store_selector_mock.go --case=underscore --with-expecter
type StoreSelector interface {
	Select(ctx context.Context, in StoreSelectInput) (*StoreSelection, error)
}

var _ StoreSelector = (*storeSelector)(nil)

type storeSelector struct {
	pipeline candidatePipeline
	logger   *slog.Logger
}

type storeChoice struct {
	link        *scopedLink
	keep        CandidateFilter
	candidates  *routingdomain.CandidateSet
	specificity specificity
}

func NewStoreSelector(resolver approuting.Resolver, listing appcatalog.ModelListing, logger *slog.Logger) StoreSelector {
	return &storeSelector{
		pipeline: candidatePipeline{resolver: resolver, listing: listing, logger: logger},
		logger:   logger,
	}
}

func (s *storeSelector) Select(ctx context.Context, in StoreSelectInput) (*StoreSelection, error) {
	intent, ref, err := parseIntent(in.Request)
	if err != nil {
		return nil, err
	}
	query := candidateQuery{
		intent:        intent,
		needed:        capabilityRequiresProviderSupport(in.Request),
		data:          in.Data,
		request:       in.Request,
		strictListing: true,
	}
	links := storeScope(in.Links)
	unknownPool := intent.IsPool() && len(links) > 0
	var best storeChoice
	for i := range links {
		link := &links[i]
		if best.link != nil && (best.specificity == specificityLiteral || !sameTier(best.link.Link, link.Link)) {
			break
		}
		choice, err := s.admit(ctx, query, link)
		if err != nil {
			s.logRefusedLink(ctx, link, err)
			unknownPool = unknownPool && errors.Is(err, routingdomain.ErrUnknownPoolAlias)
			continue
		}
		if best.link == nil || choice.specificity < best.specificity {
			best = choice
		}
	}
	switch {
	case best.link != nil:
		return &StoreSelection{
			Link: best.link.StoreLink, Keep: best.keep, Intent: intent, Ref: ref, Candidates: best.candidates,
		}, nil
	case unknownPool:
		return nil, fmt.Errorf("%w: pool %q is not configured for any linked consumer",
			routingdomain.ErrUnknownPoolAlias, intent.PoolAlias)
	default:
		return nil, ErrNoStoreConsumer
	}
}

func (s *storeSelector) admit(ctx context.Context, query candidateQuery, link *scopedLink) (storeChoice, error) {
	choice := storeChoice{link: link, keep: link.filter()}
	query.consumer, query.keep = link.Consumer, choice.keep
	candidates, err := s.pipeline.run(ctx, query)
	if err != nil {
		return storeChoice{}, err
	}
	needsDefault := query.intent.IsZero() && query.needed == ""
	admitted := false
	for _, c := range candidates.Candidates() {
		if !primaryCandidate(link.Consumer, c) || (needsDefault && c.Default == "") {
			continue
		}
		if spec := matchSpecificity(query.intent, c); !admitted || spec < choice.specificity {
			choice.specificity, admitted = spec, true
		}
	}
	if !admitted {
		return storeChoice{}, errNoPrimaryCandidate
	}
	choice.candidates = candidates
	return choice, nil
}

func (s *storeSelector) logRefusedLink(ctx context.Context, link *scopedLink, err error) {
	if s.logger == nil || !s.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	s.logger.LogAttrs(ctx, slog.LevelDebug, "store link refused",
		slog.String("consumer_id", link.Consumer.Consumer.ID.String()),
		slog.String("level", string(link.Link.Level)),
		slog.Int("priority", link.Link.Priority),
		slog.String("reason", err.Error()),
	)
}

func primaryCandidate(rc *appconsumer.RoutableConsumer, c routingdomain.Candidate) bool {
	return !c.FallbackOnly() && slices.ContainsFunc(rc.Registries, func(reg *domain.Registry) bool {
		return reg.ID == c.Registry.ID
	})
}

type specificity int

const (
	specificityLiteral specificity = iota
	specificityGlob
	specificityOpen
)

func matchSpecificity(intent routingdomain.Intent, c routingdomain.Candidate) specificity {
	switch {
	case !intent.IsQualified() && !intent.IsShortModel():
		return specificityLiteral
	case c.Allowed == nil:
		return specificityOpen
	case slices.Contains(c.Allowed, intent.Model):
		return specificityLiteral
	default:
		return specificityGlob
	}
}

func sameTier(a, b domainconsumer.AuthLink) bool {
	return a.Level.Rank() == b.Level.Rank() && a.Priority == b.Priority
}
