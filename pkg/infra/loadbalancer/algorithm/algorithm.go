package algorithm

const (
	RoundRobin         = "round-robin"
	Random             = "random"
	WeightedRoundRobin = "weighted-round-robin"
	LeastConnections   = "least-connections"
	Semantic           = "semantic"
)

func Names() []string {
	return []string{
		RoundRobin,
		Random,
		WeightedRoundRobin,
		LeastConnections,
		Semantic,
	}
}

func IsValid(name string) bool {
	switch name {
	case RoundRobin, Random, WeightedRoundRobin, LeastConnections, Semantic:
		return true
	}
	return false
}
