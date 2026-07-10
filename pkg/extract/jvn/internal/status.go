package internal

import (
	"strings"

	statusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/status"
)

// Status maps JVN's in-place invalidation markers to a normalized Status.
//
// JVN does not remove an entry it has invalidated; it keeps the record and
// prefixes the title (and sometimes the description) with a "** ... **" marker.
// go-cve-dictionary drops such entries at fetch time (fetcher/jvn/jvn.go); we
// instead preserve the record and record its state here so consumers can
// decide what to do with it. The first matching text wins; an empty result
// means no marker (treat as active).
func Status(texts ...string) statusTypes.Status {
	for _, t := range texts {
		switch {
		case strings.Contains(t, "** 削除 **"):
			return statusTypes.StatusWithdrawn
		case strings.Contains(t, "** 未確定 **"):
			return statusTypes.StatusUnconfirmed
		case strings.Contains(t, "** サポート外 **"):
			return statusTypes.StatusUnsupported
		}
	}
	return ""
}
