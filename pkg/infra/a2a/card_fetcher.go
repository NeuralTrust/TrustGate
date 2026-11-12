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

package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
)

const (
	cardFetchTimeout = 10 * time.Second
	maxCardBytes     = 1 << 20
)

var cardProbePaths = []string{"/.well-known/agent-card.json", "/.well-known/agent.json", "/agentCard/v1.0"}

var _ appregistry.CardFetcher = (*cardFetcher)(nil)

type cardFetcher struct {
	client *http.Client
	// noRedirect sends requests that carry a credential: a redirect could
	// hand it to another host.
	noRedirect *http.Client
}

// NewCardFetcher reads agent cards through client, or through a netguard
// client when client is nil. Each Resolve or Fetch has 10 s in total and reads
// at most 1 MiB per response.
func NewCardFetcher(client *http.Client) appregistry.CardFetcher {
	if client == nil {
		client = netguard.NewHTTPClient(cardFetchTimeout)
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cardFetcher{client: client, noRedirect: &noRedirect}
}

func (f *cardFetcher) Resolve(ctx context.Context, cardURL string, authorize appregistry.CardAuthorizer) (*appregistry.FetchedCard, error) {
	base, err := url.Parse(cardURL)
	if err != nil {
		return nil, fmt.Errorf("%w: card_url is not a URL", domain.ErrAgentCardUnavailable)
	}
	candidates := []string{cardURL}
	if !strings.HasSuffix(base.Path, ".json") && !strings.HasSuffix(base.Path, "/agentCard/v1.0") {
		candidates = candidates[:0]
		for _, p := range cardProbePaths {
			probe := *base
			probe.Path = strings.TrimRight(base.Path, "/") + p
			probe.RawPath = ""
			candidates = append(candidates, probe.String())
		}
	}
	ctx, cancel := context.WithTimeout(ctx, cardFetchTimeout)
	defer cancel()
	failures := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		card, err := f.get(ctx, candidate, authorize)
		if err == nil {
			return &appregistry.FetchedCard{URL: candidate, Card: card}, nil
		}
		failures = append(failures, candidate+" ("+err.Error()+")")
	}
	return nil, fmt.Errorf("%w: no agent card found; tried %s", domain.ErrAgentCardUnavailable, strings.Join(failures, ", "))
}

func (f *cardFetcher) Fetch(ctx context.Context, cardURL string, authorize appregistry.CardAuthorizer) (*appregistry.FetchedCard, error) {
	ctx, cancel := context.WithTimeout(ctx, cardFetchTimeout)
	defer cancel()
	card, err := f.get(ctx, cardURL, authorize)
	if err != nil {
		return nil, fmt.Errorf("%w: %s (%w)", domain.ErrAgentCardUnavailable, cardURL, err)
	}
	return &appregistry.FetchedCard{URL: cardURL, Card: card}, nil
}

func (f *cardFetcher) get(ctx context.Context, rawURL string, authorize appregistry.CardAuthorizer) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !netguard.AllowPrivate())) {
		return nil, errors.New("the card URL must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	client := f.client
	if authorize != nil {
		if err := authorize(req); err != nil {
			return nil, err
		}
		client = f.noRedirect
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxCardBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCardBytes {
		return nil, fmt.Errorf("card exceeds %d bytes", maxCardBytes)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return nil, errors.New("not a JSON object")
	}
	return body, nil
}
