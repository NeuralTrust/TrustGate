package version

import (
	"fmt"
	"runtime"
)

var (
	Version   = "1.7.36"
	AppName   = "TrustGate"
	BuildDate = "unknown"
)

// Info contains versioning information
type Info struct {
	AppName   string `json:"app_name"`
	Version   string `json:"version"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// GetInfo returns version information
func GetInfo() Info {
	return Info{
		AppName:   AppName,
		Version:   Version,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
