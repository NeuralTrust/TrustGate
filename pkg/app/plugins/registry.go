package plugins

import (
	"fmt"
	"sort"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

// ErrUnknownPlugin is returned when a configuration references a plugin name
// that is not present in the catalog.
var ErrUnknownPlugin = fmt.Errorf("plugin: unknown plugin")

// ErrDuplicatePlugin is returned when two plugins register under the same name.
var ErrDuplicatePlugin = fmt.Errorf("plugin: duplicate registration")

// ErrInvalidStages is returned when a plugin declares no stages or an unknown
// stage at registration time.
var ErrInvalidStages = fmt.Errorf("plugin: invalid declared stages")

// Registry is the plugin catalog: it maps a plugin name to its implementation
// and validates configuration settings against the matching plugin.
//
//go:generate mockery --name=Registry --dir=. --output=./mocks --filename=registry_mock.go --case=underscore --with-expecter
type Registry interface {
	Register(p Plugin) error
	Get(name string) (Plugin, bool)
	Validate(name string, settings map[string]any) error
	Names() []string
}

var _ Registry = (*registry)(nil)

type registry struct {
	plugins map[string]Plugin
}

// NewRegistry returns an empty catalog ready for Register calls.
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
	stages := p.Stages()
	if len(stages) == 0 {
		return fmt.Errorf("%w: %s declares no stages", ErrInvalidStages, name)
	}
	for _, s := range stages {
		if !s.IsValid() {
			return fmt.Errorf("%w: %s declares %q", ErrInvalidStages, name, s)
		}
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

func (r *registry) Names() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// pluginRunsAtStage reports whether the plugin's fixed stages include stage.
func pluginRunsAtStage(p Plugin, stage policy.Stage) bool {
	for _, s := range p.Stages() {
		if s == stage {
			return true
		}
	}
	return false
}
