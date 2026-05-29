package loadbalancer

import "time"

type HealthStatus struct {
	Healthy    bool
	LastCheck  time.Time
	LastError  error
	Failures   int
	ActiveConn int32
}
