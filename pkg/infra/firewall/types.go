package firewall

type Content struct {
	Input []string `json:"input"`
}

func (c *Content) AddInput(input []byte) {
	c.Input = append(c.Input, string(input))
}
