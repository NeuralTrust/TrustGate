package service

import (
	"context"
)

type Repository interface {
	GetService(ctx context.Context, id string) (*Service, error)
}
