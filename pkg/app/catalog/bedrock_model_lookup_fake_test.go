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

package catalog

import (
	"context"
	"sync"
)

// anyARN makes a lookup rule answer every ARN.
const anyARN = ""

// fakeLookup is a BedrockModelARNLookup scripted by rules. Rules are tried in the
// order they were declared; a rule with a count stops answering once it is used up,
// and a call no rule answers panics, which the resolver turns into a failed lookup.
type fakeLookup struct {
	mu    sync.Mutex
	rules []*lookupRule
	calls int
}

type lookupRule struct {
	arn   string
	left  int
	model string
	err   error
	run   func(ctx context.Context, creds BedrockCredentials, arn string) (string, error)
}

func (f *fakeLookup) on(arn string) *lookupRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &lookupRule{arn: arn, left: -1}
	f.rules = append(f.rules, r)
	return r
}

func (r *lookupRule) returns(model string, err error) *lookupRule {
	r.model, r.err = model, err
	return r
}

func (r *lookupRule) times(n int) *lookupRule { r.left = n; return r }

func (r *lookupRule) runs(fn func(context.Context, BedrockCredentials, string)) *lookupRule {
	r.run = func(ctx context.Context, creds BedrockCredentials, arn string) (string, error) {
		fn(ctx, creds, arn)
		return r.model, r.err
	}
	return r
}

func (r *lookupRule) runsAndReturns(fn func(context.Context, BedrockCredentials, string) (string, error)) *lookupRule {
	r.run = fn
	return r
}

func (f *fakeLookup) ResolveModelARN(ctx context.Context, creds BedrockCredentials, arn string) (string, error) {
	f.mu.Lock()
	f.calls++
	var rule *lookupRule
	for _, candidate := range f.rules {
		if candidate.left != 0 && (candidate.arn == anyARN || candidate.arn == arn) {
			rule = candidate
			if candidate.left > 0 {
				candidate.left--
			}
			break
		}
	}
	f.mu.Unlock()
	if rule == nil {
		panic("unexpected control plane lookup of " + arn)
	}
	if rule.run != nil {
		return rule.run(ctx, creds, arn)
	}
	return rule.model, rule.err
}
