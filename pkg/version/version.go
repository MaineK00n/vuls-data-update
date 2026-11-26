// Package version reports the version of the running vuls-data-update binary.
package version

import (
	"fmt"
	"runtime/debug"
)

// String returns "vuls-data-update <version>", with the version of the main
// module the Go toolchain recorded in the binary. A binary installed with
// `go install ...@<revision>` and one built in a checkout both carry a
// pseudo-version naming the commit they were built from, the latter suffixed
// "+dirty" when the checkout had uncommitted changes or untracked files. A
// build that recorded no version, such as `go run` or a test binary, reads
// "(devel)", and a binary without build info reads "(unknown)".
func String() string {
	info, ok := debug.ReadBuildInfo()
	return format(info, ok)
}

func format(info *debug.BuildInfo, ok bool) string {
	if !ok {
		return "vuls-data-update (unknown)"
	}
	return fmt.Sprintf("vuls-data-update %s", info.Main.Version)
}
