package status

import "cmp"

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
type Status string

const (
	// StatusRejected marks a CVE rejected/withdrawn by its CNA, e.g. NVD
	// "** REJECT **" / "[REJECTED CVE]", VulnCheck "Rejected reason:".
	StatusRejected Status = "rejected"
	// StatusDisputed marks a disputed CVE, e.g. NVD "** DISPUTED **".
	StatusDisputed Status = "disputed"
	// StatusWithdrawn marks a withdrawn record, e.g. JVN "** 削除 **",
	// OSV withdrawn.
	StatusWithdrawn Status = "withdrawn"
	// StatusUnconfirmed marks an unconfirmed record, e.g. JVN "** 未確定 **".
	StatusUnconfirmed Status = "unconfirmed"
	// StatusUnsupported marks an out-of-support record, e.g. JVN
	// "** サポート外 **".
	StatusUnsupported Status = "unsupported"
)

func Compare(x, y Status) int {
	return cmp.Compare(x, y)
}
