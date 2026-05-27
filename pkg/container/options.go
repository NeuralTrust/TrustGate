package container

// Option configures a Container during New.
type Option func(c *Container) error

func WithModule(m Module) Option {
	return func(c *Container) error { return m(c) }
}

func WithOverride(decorator any) Option {
	return func(c *Container) error { return c.Decorate(decorator) }
}
