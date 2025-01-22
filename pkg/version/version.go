package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current version of TrustGate
	Version = "0.1.0"

	// GitCommit is the git commit hash, injected at build time
	GitCommit = "unknown"

	// BuildDate is the build date, injected at build time
	BuildDate = "unknown"
)

// Info contains versioning information
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// GetInfo returns version information
func GetInfo() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
