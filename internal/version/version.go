// Package version reports the version of the running binary.
package version

import "runtime/debug"

// Set at link time by the release pipeline:
//
//	-ldflags "-X github.com/J466Y/WhiteTower/internal/version.version=1.2.3
//	          -X github.com/J466Y/WhiteTower/internal/version.commit=abc1234"
var (
	version = "dev"
	commit  = ""
)

// Info describes a build of White Tower.
type Info struct {
	// Version is the release version, or "dev" for local builds.
	Version string
	// Commit is the Git commit the binary was built from, or "unknown".
	Commit string
}

// Get returns the version of the running binary. When the commit was not set
// at link time, it falls back to the VCS information recorded by the Go
// toolchain.
func Get() Info {
	info := Info{Version: version, Commit: commit}
	if info.Commit != "" {
		return info
	}
	info.Commit = "unknown"
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			if setting.Key == "vcs.revision" && setting.Value != "" {
				info.Commit = setting.Value
			}
		}
	}
	return info
}
