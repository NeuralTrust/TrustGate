package websocket

import "github.com/gofiber/contrib/websocket"

type Handler interface {
	Handle(c *websocket.Conn)
}

type HandlerTransport interface {
	GetTransport() HandlerTransport
}

type HandlerTransportDTO struct {
	ForwardedHandler Handler
}

func (t *HandlerTransportDTO) GetTransport() HandlerTransport {
	return t
}
