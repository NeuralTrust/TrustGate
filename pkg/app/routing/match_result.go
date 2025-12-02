package routing

type MatchResult struct {
	Matched bool
	Params  map[string]string
}
