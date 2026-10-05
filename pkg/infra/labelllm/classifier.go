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

// Package labelllm labels traffic by asking an LLM, through the registry and
// model the gateway selected, which label of each of a consumer's label sets
// a text gets.
package labelllm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
)

const (
	capabilityChat   = "chat"
	defaultTimeout   = 15 * time.Second
	defaultMaxTokens = 4096

	maxProviderErrorRunes = 300
	defaultRetryAfter     = time.Second
	maxRetryAfter         = 30 * time.Second
)

// RegistryFinder resolves the registry selected in the gateway's traffic
// labeling config: from Postgres on the control plane, from the snapshot on a
// DB-less data plane. Either way the credentials come back decrypted.
type RegistryFinder interface {
	FindByID(ctx context.Context, id ids.RegistryID) (*registry.Registry, error)
}

// Codec is the part of the provider format adapter the classifier needs.
type Codec interface {
	AdaptRequestForProvider(body []byte, source, target adapter.Format, providerName, defaultModel string) ([]byte, error)
	DecodeResponseFor(body []byte, providerFormat adapter.Format) (*adapter.CanonicalResponse, error)
}

type Config struct {
	Timeout   time.Duration
	MaxTokens int
}

var _ trafficlabels.Classifier = (*Classifier)(nil)

type Classifier struct {
	registries RegistryFinder
	locator    factory.ProviderLocator
	codec      Codec
	timeout    time.Duration
	maxTokens  int
	now        func() time.Time
}

func New(registries RegistryFinder, locator factory.ProviderLocator, codec Codec, cfg Config) *Classifier {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = defaultMaxTokens
	}
	return &Classifier{
		registries: registries,
		locator:    locator,
		codec:      codec,
		timeout:    cfg.Timeout,
		maxTokens:  cfg.MaxTokens,
		now:        time.Now,
	}
}

// Classify makes one completion call for the text covering all the label
// sets, and returns one result per set: the label the model picked from that
// set, or none.
func (c *Classifier) Classify(ctx context.Context, in trafficlabels.ClassifyInput) (trafficlabel.Classification, error) {
	if len(in.LabelSets) == 0 || strings.TrimSpace(in.Text) == "" {
		return trafficlabel.Classification{Results: unlabeledExcept(in.LabelSets, nil)}, nil
	}
	reg, err := c.registry(ctx, in)
	if err != nil {
		return trafficlabel.Classification{}, err
	}
	client, err := c.locator.Get(reg.Provider())
	if err != nil {
		return trafficlabel.Classification{}, fmt.Errorf("%w: provider %q: %w", trafficlabel.ErrClassifierUnavailable, reg.Provider(), err)
	}
	body, target, err := c.requestBody(reg, in)
	if err != nil {
		return trafficlabel.Classification{}, err
	}
	cfg := &providers.Config{
		Options:      adapter.OpenAIProviderOptionsForTarget(reg.Provider(), target, reg.ProviderOptions()),
		Credentials:  providers.CredentialsFromTargetAuth(reg.Auth()),
		Model:        in.Model,
		DefaultModel: in.Model,
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	started := c.now()
	raw, err := client.Completions(ctx, cfg, body)
	latency := c.now().Sub(started)
	if err != nil {
		return trafficlabel.Classification{}, classifyError(err)
	}
	resp, err := c.codec.DecodeResponseFor(raw, target)
	if err != nil {
		return trafficlabel.Classification{}, fmt.Errorf("%w: decode response: %w", trafficlabel.ErrInvalidAnswer, err)
	}
	if resp == nil {
		return trafficlabel.Classification{}, fmt.Errorf("%w: empty response", trafficlabel.ErrInvalidAnswer)
	}
	results, err := parseAnswer(resp.Content, in.LabelSets)
	if err != nil {
		return trafficlabel.Classification{}, err
	}
	cls := trafficlabel.Classification{Results: results, Latency: latency}
	if resp.Usage != nil {
		cls.InputTokens = resp.Usage.InputTokens
		cls.OutputTokens = resp.Usage.OutputTokens
	}
	return cls, nil
}

func (c *Classifier) registry(ctx context.Context, in trafficlabels.ClassifyInput) (*registry.Registry, error) {
	id, err := ids.Parse[ids.RegistryKind](in.RegistryID)
	if err != nil || id.IsNil() {
		return nil, fmt.Errorf("%w: invalid registry id %q", trafficlabel.ErrClassifierUnavailable, in.RegistryID)
	}
	reg, err := c.registries.FindByID(ctx, id)
	if errors.Is(err, commonerrors.ErrNotFound) || (err == nil && reg == nil) {
		return nil, fmt.Errorf("%w: registry %s not found", trafficlabel.ErrClassifierUnavailable, id)
	}
	if err != nil {
		return nil, fmt.Errorf("labelllm: find registry: %w", err)
	}
	switch {
	case reg.GatewayID.String() != in.GatewayID:
		return nil, fmt.Errorf("%w: registry %s does not belong to gateway %s", trafficlabel.ErrClassifierUnavailable, id, in.GatewayID)
	case reg.Type != registry.TypeLLM || reg.LLMTarget == nil:
		return nil, fmt.Errorf("%w: registry %s is not an LLM registry", trafficlabel.ErrClassifierUnavailable, id)
	case reg.Auth() == nil || reg.Auth().Type == registry.AuthTypePassthrough || reg.Auth().Type == registry.AuthTypeOAuth2:
		return nil, fmt.Errorf("%w: registry %s has no stored credentials", trafficlabel.ErrClassifierUnavailable, id)
	}
	return reg, nil
}

func (c *Classifier) requestBody(reg *registry.Registry, in trafficlabels.ClassifyInput) ([]byte, adapter.Format, error) {
	body, err := buildRequest(in.Model, in.LabelSets, in.Text, c.maxTokens)
	if err != nil {
		return nil, "", fmt.Errorf("labelllm: build request: %w", err)
	}
	provider := reg.Provider()
	target := adapter.ResolveTargetFormatForCapability(provider, capabilityChat, adapter.FormatOpenAI, reg.ProviderOptions())
	if !adapter.ShouldPassthroughSameWireFormat(adapter.FormatOpenAI, target) {
		adapted, err := c.codec.AdaptRequestForProvider(body, adapter.FormatOpenAI, target, provider, in.Model)
		if err != nil {
			return nil, "", fmt.Errorf("%w: adapt request (%s->%s): %w", trafficlabel.ErrClassifierUnavailable, adapter.FormatOpenAI, target, err)
		}
		body = adapter.CarryModel(body, adapted)
	}
	return adapter.NormalizeRequestForProvider(provider, target, body), target, nil
}

// classifyError maps a provider failure onto what the worker acts on: a
// saturated provider pauses the worker, a request the provider refuses
// (credentials, unknown model) is a configuration problem that retrying cannot
// fix, and anything else is retried behind the breaker.
func classifyError(err error) error {
	be, ok := registry.IsBackendError(err)
	if !ok {
		return fmt.Errorf("labelllm: completion: %w", err)
	}
	switch {
	case be.StatusCode == http.StatusTooManyRequests || be.StatusCode == http.StatusServiceUnavailable:
		return &trafficlabel.BackpressureError{RetryAfter: retryAfter(be.RetryAfter)}
	case be.StatusCode >= 400 && be.StatusCode < 500 && be.StatusCode != http.StatusRequestTimeout:
		if msg := providerErrorMessage(be.Body); msg != "" {
			return fmt.Errorf("%w: provider answered %d: %s", trafficlabel.ErrClassifierUnavailable, be.StatusCode, msg)
		}
		return fmt.Errorf("%w: provider answered %d", trafficlabel.ErrClassifierUnavailable, be.StatusCode)
	default:
		return fmt.Errorf("labelllm: completion: %w", err)
	}
}

// providerErrorMessage reads the message of a provider's error envelope
// ({"error":{"message":...}} for OpenAI and Anthropic alike, or a bare
// {"error":"..."} / {"message":"..."}), so a refused
// call says why in the log. Only that field is kept, cut to a bounded length,
// never the raw body.
func providerErrorMessage(body []byte) string {
	var envelope struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if len(body) == 0 || json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	msg := envelope.Message
	var nested struct {
		Message string `json:"message"`
	}
	var flat string
	switch {
	case json.Unmarshal(envelope.Error, &nested) == nil && nested.Message != "":
		msg = nested.Message
	case json.Unmarshal(envelope.Error, &flat) == nil && flat != "":
		msg = flat
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if r := []rune(msg); len(r) > maxProviderErrorRunes {
		msg = string(r[:maxProviderErrorRunes]) + "…"
	}
	return msg
}

func retryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return defaultRetryAfter
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		if seconds <= 0 {
			return defaultRetryAfter
		}
		return min(time.Duration(seconds)*time.Second, maxRetryAfter)
	}
	if at, err := http.ParseTime(header); err == nil {
		if d := time.Until(at); d > 0 {
			return min(d, maxRetryAfter)
		}
	}
	return defaultRetryAfter
}
