// Package container wraps uber/dig with per-context modules.
package container

import "go.uber.org/dig"

type Container struct {
	*dig.Container
}

type Module func(c *Container) error

func New(opts ...Option) (*Container, error) {
	c := &Container{Container: dig.New()}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}
