package status

import (
	"cmp"
	"strings"
)

// Status is the lifecycle state of a record as published by a data source.
//
// It is carried on both advisory and vulnerability content so each source can
// record the state of the entity it actually publishes: an advisory-keyed
// source (e.g. JVN, whose root is a JVNDB record) sets it on the advisory
// content, while a CVE-keyed source (e.g. NVD / VulnCheck, whose root is the
// CVE) sets it on the vulnerability content.
//
// The raw upstream marker (e.g. a "** REJECT **" / "** 削除 **" title or
// description prefix) is still preserved verbatim in Title/Description; Status
// is the normalized, machine-readable projection of it so consumers do not have
// to string-match. An empty Status means unspecified (treat as active).
//
// Status is an open string, not a closed enum. The constants below are the
// invalidation subset that consumers filter on (a rejected/withdrawn/etc.
// record should be dropped from detection). Any other value is an informational
// source status carried through verbatim — for example NVD/VulnCheck record
// their analysis progress (analyzed, modified, deferred, ...) via Normalize —
// which consumers may display (e.g. in `vuls db search`) but must not treat as
// invalidation.
type Status string

const (
	// StatusRejected marks a CVE rejected/withdrawn by its CNA, e.g. NVD /
	// VulnCheck vulnStatus "Rejected", MITRE/Debian "REJECTED".
	StatusRejected Status = "rejected"
	// StatusWithdrawn marks a withdrawn record, e.g. JVN "** 削除 **",
	// OSV withdrawn.
	StatusWithdrawn Status = "withdrawn"
	// StatusUnconfirmed marks an unconfirmed record, e.g. JVN "** 未確定 **".
	StatusUnconfirmed Status = "unconfirmed"
	// StatusUnsupported marks an out-of-support record, e.g. JVN
	// "** サポート外 **".
	StatusUnsupported Status = "unsupported"
)

// Normalize projects a raw upstream status string (e.g. an NVD/VulnCheck
// vulnStatus like "Awaiting Analysis" or "Rejected") into a Status token by
// lower-casing and replacing spaces with hyphens. Invalidation values collapse
// onto the constants above (e.g. "Rejected" -> StatusRejected); other values
// (e.g. "analyzed", "deferred") are preserved as informational, source-specific
// strings that consumers may display but must not treat as invalidation. An
// empty input yields an empty Status.
func Normalize(s string) Status {
	return Status(strings.ReplaceAll(strings.ToLower(s), " ", "-"))
}

func Compare(x, y Status) int {
	return cmp.Compare(x, y)
}
