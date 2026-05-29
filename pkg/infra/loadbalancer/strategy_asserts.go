package loadbalancer

import "github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/strategies"

var (
	_ Strategy = (*strategies.RoundRobin)(nil)
	_ Strategy = (*strategies.Random)(nil)
	_ Strategy = (*strategies.WeightedRoundRobin)(nil)
	_ Strategy = (*strategies.LeastConnections)(nil)
	_ Strategy = (*strategies.Semantic)(nil)
)
