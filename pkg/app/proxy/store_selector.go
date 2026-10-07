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
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// ErrNoStoreConsumer is returned when none of the caller's personal consumers
// admits the request's model.
var ErrNoStoreConsumer = fmt.Errorf("store: no consumer admits the request: %w", routingdomain.ErrModelDenied)

var errNoPrimaryCandidate = fmt.Errorf("store: no primary candidate admits the request: %w", routingdomain.ErrModelDenied)

// StoreSelectInput is a store request and the personal consumers its key
// reaches, in the order Data.StoreLinks returns them.
type StoreSelectInput struct {
	Links   []appconsumer.StoreLink
	Data    *appconsumer.Data
	Request *infracontext.RequestContext
}

// StoreSelection is the personal consumer that serves a store request and the
// routing already resolved against it.
type StoreSelection struct {
	Link appconsumer.StoreLink
	ResolvedRouting
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
	candidates  *routingdomain.CandidateSet
	specificity specificity
}

// NewStoreSelector returns the StoreSelector the store route uses.
func NewStoreSelector(resolver approuting.Resolver, listing appcatalog.ModelListing, logger *slog.Logger) StoreSelector {
	return &storeSelector{
		pipeline: candidatePipeline{resolver: resolver, listing: listing, logger: logger},
		logger:   logger,
	}
}

func (s *storeSelector) Select(ctx context.Context, in StoreSelectInput) (*StoreSelection, error) {
	if ambiguousChatBody(in.Request) {
		return nil, ErrAmbiguousRequestBody
	}
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
	var best storeChoice
	var refused refusals
	for i := range links {
		link := &links[i]
		if best.link != nil && (best.specificity == specificityLiteral || !sameTier(best.link.Link, link.Link)) {
			break
		}
		choice, err := s.admit(ctx, query, link)
		if err != nil {
			s.logRefusedLink(ctx, link, err)
			refused.add(err)
			continue
		}
		if best.link == nil || choice.specificity < best.specificity {
			best = choice
		}
	}
	if best.link == nil {
		return nil, refused.err(intent)
	}
	return &StoreSelection{
		Link:            best.link.StoreLink,
		ResolvedRouting: ResolvedRouting{Intent: intent, Ref: ref, Candidates: best.candidates},
	}, nil
}

// refusals collects why each link refused a request. When every link refused
// it for the same reason other than the model, the caller gets that reason
// (an unknown pool, a capability no provider supports, no backend) and not a
// permissions error it would read as a missing grant.
type refusals struct {
	kind    error
	count   int
	uniform bool
}

func (r *refusals) add(err error) {
	kind := refusalKind(err)
	if r.count == 0 {
		r.kind, r.uniform = kind, true
	} else if kind != r.kind {
		r.uniform = false
	}
	r.count++
}

func (r *refusals) err(intent routingdomain.Intent) error {
	if r.count == 0 || !r.uniform || r.kind == nil {
		return ErrNoStoreConsumer
	}
	if r.kind == routingdomain.ErrUnknownPoolAlias {
		return fmt.Errorf("%w: pool %q is not configured for any linked consumer", routingdomain.ErrUnknownPoolAlias, intent.PoolAlias)
	}
	return fmt.Errorf("store: no linked consumer can serve the request: %w", r.kind)
}

func refusalKind(err error) error {
	for _, kind := range []error{routingdomain.ErrUnknownPoolAlias, ErrCapabilityNotSupported, ErrNoBackendsInPool} {
		if errors.Is(err, kind) {
			return kind
		}
	}
	return nil
}

func (s *storeSelector) admit(ctx context.Context, query candidateQuery, link *scopedLink) (storeChoice, error) {
	choice := storeChoice{link: link}
	query.consumer, query.keep = link.Consumer, link.filter()
	candidates, err := s.pipeline.run(ctx, query)
	if err != nil {
		return storeChoice{}, err
	}
	needsDefault := query.intent.IsZero() && query.needed == ""
	admitted := false
	for _, c := range candidates.Candidates() {
		if !link.primary(c) || (needsDefault && c.Default == "") {
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
