package fixstatus

import "cmp"

type FixStatus struct {
	Class  Class  `json:"class,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

type Class string

const (
	ClassUnfixed Class = "unfixed"
	ClassFixed   Class = "fixed"
	ClassUnknown Class = "unknown"
)

func Compare(x, y FixStatus) int {
	return cmp.Or(
		cmp.Compare(x.Class, y.Class),
		cmp.Compare(x.Vendor, y.Vendor),
	)
}
