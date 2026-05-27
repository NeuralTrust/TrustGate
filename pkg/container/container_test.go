package container_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/container"
)

type pinger interface {
	Ping() string
}

type realPinger struct{}

func (realPinger) Ping() string { return "real" }

type fakePinger struct{}

func (fakePinger) Ping() string { return "fake" }

func TestNew_AppliesModulesInOrder(t *testing.T) {
	var calls []string
	mod := func(name string) container.Module {
		return func(*container.Container) error {
			calls = append(calls, name)
			return nil
		}
	}

	_, err := container.New(
		container.WithModule(mod("a")),
		container.WithModule(mod("b")),
		container.WithModule(mod("c")),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	want := []string{"a", "b", "c"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i, name := range want {
		if calls[i] != name {
			t.Errorf("calls[%d] = %s, want %s", i, calls[i], name)
		}
	}
}

func TestWithOverride_SwapsProvider(t *testing.T) {
	c, err := container.New(
		container.WithModule(func(c *container.Container) error {
			return c.Provide(func() pinger { return realPinger{} })
		}),
		container.WithOverride(func(_ pinger) pinger { return fakePinger{} }),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Invoke(func(p pinger) {
		if got := p.Ping(); got != "fake" {
			t.Errorf("Ping = %q, want %q (override should win)", got, "fake")
		}
	}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
}

func TestNew_PropagatesContextProvider(t *testing.T) {
	c, err := container.New(container.WithModule(func(c *container.Container) error {
		return c.Provide(func() context.Context { return context.Background() })
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Invoke(func(ctx context.Context) {
		if ctx == nil {
			t.Fatal("nil context resolved")
		}
	}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
}
