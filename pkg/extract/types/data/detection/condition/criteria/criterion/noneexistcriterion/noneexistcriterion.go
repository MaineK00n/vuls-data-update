package noneexistcriterion

import (
	"cmp"

	"github.com/pkg/errors"

	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/source"
)

// PackageType is a string so that unmarshaling never validates against the
// known set: data produced by a newer vuls-data-update (carrying package
// types this build does not know) still round-trips losslessly instead of
// failing the whole read.
type PackageType string

const (
	PackageTypeBinary PackageType = "binary"
	PackageTypeSource PackageType = "source"

	PackageTypeUnknown PackageType = "unknown"
)

// PackageTypes returns every PackageType this build knows, in declaration
// order. Consumers (vuls2, vuls0) diff this list against a newer
// vuls-data-update in CI to detect enum additions that require a dependency
// bump. The known set must be append-only.
func PackageTypes() []PackageType {
	return []PackageType{
		PackageTypeBinary,
		PackageTypeSource,
		PackageTypeUnknown,
	}
}

type Criterion struct {
	Type   PackageType          `json:"type,omitempty"`
	Binary *binaryTypes.Package `json:"binary,omitempty"`
	Source *sourceTypes.Package `json:"source,omitempty"`
}

func (c *Criterion) Sort() {
	switch c.Type {
	case PackageTypeBinary:
		c.Binary.Sort()
	case PackageTypeSource:
		c.Source.Sort()
	default:
	}
}

func Compare(x, y Criterion) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		func() int {
			switch x.Type {
			case PackageTypeBinary:
				switch {
				case x.Binary == nil && y.Binary == nil:
					return 0
				case x.Binary == nil && y.Binary != nil:
					return -1
				case x.Binary != nil && y.Binary == nil:
					return +1
				default:
					return binaryTypes.Compare(*x.Binary, *y.Binary)
				}
			case PackageTypeSource:
				switch {
				case x.Source == nil && y.Source == nil:
					return 0
				case x.Source == nil && y.Source != nil:
					return -1
				case x.Source != nil && y.Source == nil:
					return +1
				default:
					return sourceTypes.Compare(*x.Source, *y.Source)
				}
			default:
				return 0
			}
		}(),
	)
}

type Query struct {
	Binaries []binaryTypes.Query
	Sources  []sourceTypes.Query
}

func (c Criterion) Accept(query Query, repositories []string) (bool, error) {
	switch c.Type {
	case PackageTypeBinary:
		if len(query.Binaries) == 0 {
			return false, errors.New("query is not set for Binary Package")
		}
		for _, q := range query.Binaries {
			isAccepted, err := c.Binary.Accept(q, repositories)
			if err != nil {
				return false, errors.Wrap(err, "binary package accept")
			}
			if isAccepted {
				return false, nil
			}
		}
		return true, nil
	case PackageTypeSource:
		if len(query.Sources) == 0 {
			return false, errors.New("query is not set for Source Package")
		}
		for _, q := range query.Sources {
			isAccepted, err := c.Source.Accept(q, repositories)
			if err != nil {
				return false, errors.Wrap(err, "source package accept")
			}
			if isAccepted {
				return false, nil
			}
		}
		return true, nil
	default:
		// A PackageType this build cannot evaluate — Unknown, unset, or a
		// value from a newer vuls-data-update — reports "does not accept"
		// (not affected) so detection skips the criterion instead of
		// aborting. For a none-exist criterion this is the conservative
		// direction: it under-detects rather than falsely claiming absence.
		return false, nil
	}
}
