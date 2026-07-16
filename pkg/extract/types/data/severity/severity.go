package severity

import (
	"cmp"

	v2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	v31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	v40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vendorTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/vendor"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

type Severity struct {
	Type    SeverityType      `json:"type,omitempty"`
	Source  string            `json:"source,omitempty"`
	Vendor  *string           `json:"vendor,omitempty"`
	CVSSv2  *v2Types.CVSSv2   `json:"cvss_v2,omitempty"`
	CVSSv30 *v30Types.CVSSv30 `json:"cvss_v30,omitempty"`
	CVSSv31 *v31Types.CVSSv31 `json:"cvss_v31,omitempty"`
	CVSSv40 *v40Types.CVSSv40 `json:"cvss_v40,omitempty"`
}

// SeverityType is a string so that unmarshaling never validates against the
// known set: data produced by a newer vuls-data-update (carrying severity
// types this build does not know) still round-trips losslessly instead of
// failing the whole read.
type SeverityType string

const (
	SeverityTypeVendor  SeverityType = "vendor"
	SeverityTypeCVSSv2  SeverityType = "cvss_v2"
	SeverityTypeCVSSv30 SeverityType = "cvss_v30"
	SeverityTypeCVSSv31 SeverityType = "cvss_v31"
	SeverityTypeCVSSv40 SeverityType = "cvss_v40"
)

// SeverityTypes returns every SeverityType this build knows, in declaration
// order. Consumers (vuls2, vuls0) diff this list against a newer
// vuls-data-update in CI to detect enum additions that require a dependency
// bump. The known set must be append-only.
func SeverityTypes() []SeverityType {
	return []SeverityType{
		SeverityTypeVendor,
		SeverityTypeCVSSv2,
		SeverityTypeCVSSv30,
		SeverityTypeCVSSv31,
		SeverityTypeCVSSv40,
	}
}

// Compare orders t against u by vocabulary rank — the declaration order of
// SeverityTypes() — preserving the canonical output order from before the
// string conversion. Values outside the vocabulary sort after every known
// value, lexicographically among themselves.
func (t SeverityType) Compare(u SeverityType) int {
	return enum.Compare(SeverityTypes(), t, u)
}

func Compare(x, y Severity) int {
	return cmp.Or(
		cmp.Compare(x.Source, y.Source),
		x.Type.Compare(y.Type),
		func() int {
			switch x.Type {
			case SeverityTypeVendor:
				switch {
				case x.Vendor == nil && y.Vendor == nil:
					return 0
				case x.Vendor == nil && y.Vendor != nil:
					return -1
				case x.Vendor != nil && y.Vendor == nil:
					return +1
				default:
					return vendorTypes.Compare(x.Source, *x.Vendor, *y.Vendor)
				}
			case SeverityTypeCVSSv2:
				switch {
				case x.CVSSv2 == nil && y.CVSSv2 == nil:
					return 0
				case x.CVSSv2 == nil && y.CVSSv2 != nil:
					return -1
				case x.CVSSv2 != nil && y.CVSSv2 == nil:
					return +1
				default:
					return v2Types.Compare(*x.CVSSv2, *y.CVSSv2)
				}
			case SeverityTypeCVSSv30:
				switch {
				case x.CVSSv30 == nil && y.CVSSv30 == nil:
					return 0
				case x.CVSSv30 == nil && y.CVSSv30 != nil:
					return -1
				case x.CVSSv30 != nil && y.CVSSv30 == nil:
					return +1
				default:
					return v30Types.Compare(*x.CVSSv30, *y.CVSSv30)
				}
			case SeverityTypeCVSSv31:
				switch {
				case x.CVSSv31 == nil && y.CVSSv31 == nil:
					return 0
				case x.CVSSv31 == nil && y.CVSSv31 != nil:
					return -1
				case x.CVSSv31 != nil && y.CVSSv31 == nil:
					return +1
				default:
					return v31Types.Compare(*x.CVSSv31, *y.CVSSv31)
				}
			case SeverityTypeCVSSv40:
				switch {
				case x.CVSSv40 == nil && y.CVSSv40 == nil:
					return 0
				case x.CVSSv40 == nil && y.CVSSv40 != nil:
					return -1
				case x.CVSSv40 != nil && y.CVSSv40 == nil:
					return +1
				default:
					return v40Types.Compare(*x.CVSSv40, *y.CVSSv40)
				}
			default:
				return 0
			}
		}(),
	)
}
