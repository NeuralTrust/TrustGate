package pii_entities

// MaxDetectContentLength is the maximum input size for DetectAll.
// Inputs exceeding this limit are rejected to prevent excessive bitmap allocation.
const MaxDetectContentLength = 1 << 20 // 1 MB

// Match represents a single PII detection result with its byte position.
type Match struct {
	Entity Entity
	Value  string
	Start  int
	End    int
}

// DetectAll runs tiered PII detection on content, returning non-overlapping
// matches sorted by position. Only entities present in the enabled map are
// considered. Higher tiers (lower number) claim byte ranges before lower tiers
// via a position bitmap, and validator functions filter false positives before
// a range is claimed.
func DetectAll(content string, enabled map[Entity]bool) []Match {
	if len(content) == 0 || len(content) > MaxDetectContentLength {
		return nil
	}

	occupied := make([]bool, len(content))
	var results []Match

	for _, tier := range tierOrder {
		for _, entity := range tier {
			if !enabled[entity] {
				continue
			}
			info, ok := Entities[entity]
			if !ok {
				continue
			}
			locs := info.Pattern.FindAllStringIndex(content, -1)
			for _, loc := range locs {
				if anyOccupied(occupied, loc[0], loc[1]) {
					continue
				}
				value := content[loc[0]:loc[1]]
				if info.Validate != nil && !info.Validate(value) {
					continue
				}
				markOccupied(occupied, loc[0], loc[1])
				results = append(results, Match{
					Entity: entity,
					Value:  value,
					Start:  loc[0],
					End:    loc[1],
				})
			}
		}
	}
	return results
}

func anyOccupied(bitmap []bool, start, end int) bool {
	for i := start; i < end; i++ {
		if bitmap[i] {
			return true
		}
	}
	return false
}

func markOccupied(bitmap []bool, start, end int) {
	for i := start; i < end; i++ {
		bitmap[i] = true
	}
}
