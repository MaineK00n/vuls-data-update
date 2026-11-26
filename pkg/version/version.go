// Package version reports the version of vuls-data-update a binary was built
// with.
package version

import (
	"fmt"
	"runtime/debug"
)

const modulePath = "github.com/MaineK00n/vuls-data-update"

// String returns "vuls-data-update <version>", with the version of the
// vuls-data-update module the Go toolchain recorded in the binary: the main
// module in vuls-data-update's own binary, a dependency in a program built on
// its packages. A binary installed with `go install ...@<revision>` and one
// built in a checkout both carry a pseudo-version naming the commit they were
// built from, the latter suffixed "+dirty" when the checkout had uncommitted
// changes or untracked files. A build that recorded no version, such as
// `go run` or a test binary, reads "(devel)", as does a dependency replaced by
// a directory, and a binary without build info, or without the module, reads
// "(unknown)".
func String() string {
	info, ok := debug.ReadBuildInfo()
	return format(info, ok)
}

func format(info *debug.BuildInfo, ok bool) string {
	if !ok {
		return "vuls-data-update (unknown)"
	}

	m := func() *debug.Module {
		if info.Main.Path == modulePath {
			return &info.Main
		}
		for _, d := range info.Deps {
			if d.Path == modulePath {
				return d
			}
		}
		return nil
	}()
	if m == nil {
		return "vuls-data-update (unknown)"
	}
	if m.Replace != nil {
		m = m.Replace
	}
	if m.Version == "" {
		return "vuls-data-update (devel)"
	}
	return fmt.Sprintf("vuls-data-update %s", m.Version)
}
