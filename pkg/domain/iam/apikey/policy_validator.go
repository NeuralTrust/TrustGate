package apikey

import (
	"context"

	"github.com/google/uuid"
)

type PolicyValidator interface {
	Validate(
		ctx context.Context,
		subjectType SubjectType,
		subject uuid.UUID,
		policies []string,
	) error
}
