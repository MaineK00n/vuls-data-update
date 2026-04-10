package vulncheck

import (
	"cmp"
	"slices"

	reportedExploitationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck/reportedexploitation"
	xdbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck/xdb"
)

type VulnCheck struct {
	XDB                  []xdbTypes.XDB                                  `json:"xdb,omitempty"`
	ReportedExploitation []reportedExploitationTypes.ReportedExploitation `json:"reportedExploitation,omitempty"`
}

func (v *VulnCheck) Sort() {
	slices.SortFunc(v.XDB, xdbTypes.Compare)
	slices.SortFunc(v.ReportedExploitation, reportedExploitationTypes.Compare)
}

func Compare(x, y VulnCheck) int {
	return cmp.Or(
		slices.CompareFunc(x.XDB, y.XDB, xdbTypes.Compare),
		slices.CompareFunc(x.ReportedExploitation, y.ReportedExploitation, reportedExploitationTypes.Compare),
	)
}
