// Package version reports the version of the running binary.
package version

import "runtime/debug"

// Development is the version of the builds that the release pipeline did
// not make.
const Development = "dev"

// Set at link time by the release pipeline:
//
//	-ldflags "-X github.com/J466Y/WhiteTower/internal/version.version=1.2.3
//	          -X github.com/J466Y/WhiteTower/internal/version.commit=abc1234"
var (
	version = Development
	commit  = ""
)

// Info describes a build of White Tower.
type Info struct {
	// Version is the release version, or "dev" for local builds.
	Version string
	// Commit is the Git commit the binary was built from, or "unknown".
	Commit string
}

// Release reports whether the release pipeline built the binary: such a
// build refuses the settings meant for development (threat model, T-61).
func (i Info) Release() bool { return i.Version != Development }

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
