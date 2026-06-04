package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

const (
	duplicateFirstSuffix  = 2
	duplicateMaxAttempts  = 50
	duplicateNameScanSize = 1000
	duplicateNameMaxLen   = 255
	duplicateFallbackBase = "copy"
)

var trailingSuffixRe = regexp.MustCompile(`^(.+?)\s+(\d+)$`)

//go:generate mockery --name=Duplicator --dir=. --output=./mocks --filename=policy_duplicator_mock.go --case=underscore --with-expecter
type Duplicator interface {
	Duplicate(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error)
}

var _ Duplicator = (*duplicator)(nil)

type duplicator struct {
	finder  Finder
	creator Creator
	logger  *slog.Logger
}

func NewDuplicator(finder Finder, creator Creator, logger *slog.Logger) Duplicator {
	return &duplicator{finder: finder, creator: creator, logger: logger}
}

func (d *duplicator) Duplicate(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error) {
	src, err := d.finder.FindByID(ctx, gatewayID, id)
	if err != nil {
		return nil, err
	}

	base, start := baseAndStart(src.Name)
	taken, err := d.takenNames(ctx, gatewayID, base)
	if err != nil {
		return nil, err
	}

	n := nextSuffix(base, start, taken)
	for attempt := 0; attempt < duplicateMaxAttempts; attempt++ {
		p, createErr := d.creator.Create(ctx, CreateInput{
			GatewayID: gatewayID,
			Name:      composeName(base, n),
			Slug:      src.Slug,
			Enabled:   src.Enabled,
			Priority:  src.Priority,
			Parallel:  src.Parallel,
			Settings:  cloneSettings(src.Settings),
			Stages:    cloneStages(src.Stages),
		})
		if createErr == nil {
			return p, nil
		}
		if !errors.Is(createErr, domain.ErrAlreadyExists) {
			return nil, createErr
		}
		n++
	}
	d.logger.Warn("policy duplicate exhausted name attempts",
		slog.String("policy_id", id.String()),
		slog.String("base_name", base),
		slog.Int("attempts", duplicateMaxAttempts),
	)
	return nil, fmt.Errorf(
		"policy: duplicate %q: exhausted %d name attempts: %w",
		src.Name, duplicateMaxAttempts, domain.ErrAlreadyExists,
	)
}

func (d *duplicator) takenNames(ctx context.Context, gatewayID ids.GatewayID, base string) (map[string]struct{}, error) {
	items, _, err := d.finder.List(ctx, domain.ListFilter{
		GatewayID:    gatewayID,
		NameContains: base,
		Page:         1,
		Size:         duplicateNameScanSize,
	})
	if err != nil {
		return nil, err
	}
	taken := make(map[string]struct{}, len(items))
	for _, p := range items {
		taken[p.Name] = struct{}{}
	}
	return taken, nil
}

// baseAndStart strips a trailing " <n>" so re-duplicating extends the same
// sequence, and starts the search at n+1 so the copy never numbers below its source.
func baseAndStart(name string) (string, int) {
	trimmed := strings.TrimSpace(name)
	base := trimmed
	start := duplicateFirstSuffix
	if m := trailingSuffixRe.FindStringSubmatch(trimmed); m != nil {
		base = strings.TrimSpace(m[1])
		if num, err := strconv.Atoi(m[2]); err == nil && num >= start {
			start = num + 1
		}
	}
	if base == "" {
		base = duplicateFallbackBase
	}
	return base, start
}

func nextSuffix(base string, start int, taken map[string]struct{}) int {
	for n := start; ; n++ {
		if _, ok := taken[composeName(base, n)]; !ok {
			return n
		}
	}
}

func composeName(base string, n int) string {
	suffix := strconv.Itoa(n)
	if len(base)+1+len(suffix) > duplicateNameMaxLen {
		base = strings.TrimRight(truncateToBytes(base, duplicateNameMaxLen-len(suffix)-1), " ")
	}
	return strings.TrimSpace(base + " " + suffix)
}

func truncateToBytes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func cloneSettings(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneSettings(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = cloneValue(e)
		}
		return out
	default:
		return v
	}
}

func cloneStages(in []domain.Stage) []domain.Stage {
	if in == nil {
		return nil
	}
	out := make([]domain.Stage, len(in))
	copy(out, in)
	return out
}
