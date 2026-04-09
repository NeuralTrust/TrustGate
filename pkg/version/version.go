package version

import (
	"fmt"
	"os"
	"runtime"
)

var (
	Version   = "1.18.13"
	AppName   = "TrustGate"
	BuildDate = "unknown"
)

func init() {
	// Allow runtime override via env var (used in image promotion: dev → prod).
	// Kubernetes injects APPLICATION_VERSION with the release tag, overriding
	// whatever was compiled in via ldflags.
	if v := os.Getenv("APPLICATION_VERSION"); v != "" {
		Version = v
	}
}

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
