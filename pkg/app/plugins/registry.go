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

package plugins

import (
	"fmt"
	"sort"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

var ErrUnknownPlugin = fmt.Errorf("plugin: unknown plugin")
var ErrDuplicatePlugin = fmt.Errorf("plugin: duplicate registration")
var ErrInvalidStages = fmt.Errorf("plugin: invalid declared stages")

//go:generate mockery --name=Registry --dir=. --output=./mocks --filename=registry_mock.go --case=underscore --with-expecter
type Registry interface {
	Register(p Plugin) error
	Get(name string) (Plugin, bool)
	Validate(name string, settings map[string]any) error
	ValidateStages(name string, selected []policy.Stage) error
	Names() []string
}

var _ Registry = (*registry)(nil)

type registry struct {
	plugins map[string]Plugin
}

func NewRegistry() Registry {
	return &registry{plugins: make(map[string]Plugin)}
}

func (r *registry) Register(p Plugin) error {
	if p == nil {
		return fmt.Errorf("%w: nil plugin", ErrUnknownPlugin)
	}
	name := p.Name()
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrUnknownPlugin)
	}
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicatePlugin, name)
	}
	supported := p.SupportedStages()
	if len(supported) == 0 {
		return fmt.Errorf("%w: %s declares no supported stages", ErrInvalidStages, name)
	}
	for _, s := range supported {
		if !s.IsValid() {
			return fmt.Errorf("%w: %s supports %q", ErrInvalidStages, name, s)
		}
	}
	for _, s := range p.MandatoryStages() {
		if !s.IsValid() {
			return fmt.Errorf("%w: %s requires %q", ErrInvalidStages, name, s)
		}
		if !containsStage(supported, s) {
			return fmt.Errorf("%w: %s requires %q outside its supported stages", ErrInvalidStages, name, s)
		}
	}
	if err := validateDeclaredModes(name, p.SupportedModes()); err != nil {
		return err
	}
	r.plugins[name] = p
	return nil
}

func (r *registry) Get(name string) (Plugin, bool) {
	p, ok := r.plugins[name]
	return p, ok
}

func (r *registry) Validate(name string, settings map[string]any) error {
	p, ok := r.plugins[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownPlugin, name)
	}
	return p.ValidateConfig(settings)
}

func (r *registry) ValidateStages(name string, selected []policy.Stage) error {
	p, ok := r.plugins[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownPlugin, name)
	}
	return ValidateStages(p, selected)
}

func (r *registry) Names() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func containsStage(stages []policy.Stage, stage policy.Stage) bool {
	for _, s := range stages {
		if s == stage {
			return true
		}
	}
	return false
}
