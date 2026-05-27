// Package version exposes build metadata injected via ldflags.
package version

import (
	"fmt"
	"os"
	"runtime"
)

var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
	AppName   = "AgentGateway"
)

func init() {
	if v := os.Getenv("APPLICATION_VERSION"); v != "" {
		Version = v
	}
}

type Info struct {
	AppName   string `json:"app_name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func GetInfo() Info {
	return Info{
		AppName:   AppName,
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func String() string {
	return fmt.Sprintf("%s %s (commit=%s build=%s %s)",
		AppName, Version, Commit, BuildDate, runtime.Version())
}
