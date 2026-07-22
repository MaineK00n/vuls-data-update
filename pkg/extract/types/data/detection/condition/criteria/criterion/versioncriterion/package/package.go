package criterionpackage

import (
	"cmp"

	"github.com/pkg/errors"

	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	languageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/language"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/internal/enum"
)

// PackageType is a string so that unmarshaling never validates against the
// known set: data produced by a newer vuls-data-update (carrying package
// types this build does not know) still round-trips losslessly instead of
// failing the whole read.
type PackageType string

const (
	PackageTypeBinary   PackageType = "binary"
	PackageTypeSource   PackageType = "source"
	PackageTypeLanguage PackageType = "language"
)

// PackageTypes returns every PackageType this build knows, in declaration
// order. Consumers (vuls2, vuls0) diff this list against a newer
// vuls-data-update in CI to detect enum additions that require a dependency
// bump. The known set must be append-only.
func PackageTypes() []PackageType {
	return []PackageType{
		PackageTypeBinary,
		PackageTypeSource,
		PackageTypeLanguage,
	}
}

// Compare orders t against u by vocabulary rank — the declaration order of
// PackageTypes() — preserving the canonical output order from before the
// string conversion. Values outside the vocabulary sort after every known
// value, lexicographically among themselves.
func (t PackageType) Compare(u PackageType) int {
	return vocabulary.Compare(t, u)
}

// Known reports whether t is in this build's vocabulary. Data from a newer
// vuls-data-update may carry values for which Known is false.
func (t PackageType) Known() bool {
	return vocabulary.Contains(t)
}

var vocabulary = enum.NewVocabulary(PackageTypes())

type Package struct {
	Type     PackageType            `json:"type,omitempty"`
	Binary   *binaryTypes.Package   `json:"binary,omitempty"`
	Source   *sourceTypes.Package   `json:"source,omitempty"`
	Language *languageTypes.Package `json:"language,omitempty"`
}

func (p *Package) Sort() {
	switch p.Type {
	case PackageTypeBinary:
		p.Binary.Sort()
	case PackageTypeSource:
		p.Source.Sort()
	case PackageTypeLanguage:
		p.Language.Sort()
	default:
	}
}

func Compare(x, y Package) int {
	return cmp.Or(
		x.Type.Compare(y.Type),
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
			case PackageTypeLanguage:
				switch {
				case x.Language == nil && y.Language == nil:
					return 0
				case x.Language == nil && y.Language != nil:
					return -1
				case x.Language != nil && y.Language == nil:
					return +1
				default:
					return languageTypes.Compare(*x.Language, *y.Language)
				}
			default:
				return 0
			}
		}(),
	)
}

type Query struct {
	Binary   *binaryTypes.Query
	Source   *sourceTypes.Query
	Language *languageTypes.Query
}

func (p Package) Accept(query Query, repositories []string) (bool, error) {
	switch p.Type {
	case PackageTypeBinary:
		if query.Binary == nil {
			return false, errors.New("query is not set for Binary Package")
		}
		isAccepted, err := p.Binary.Accept(*query.Binary, repositories)
		if err != nil {
			return false, errors.Wrap(err, "binary package accept")
		}
		return isAccepted, nil
	case PackageTypeSource:
		if query.Source == nil {
			return false, errors.New("query is not set for Source Package")
		}
		isAccepted, err := p.Source.Accept(*query.Source, repositories)
		if err != nil {
			return false, errors.Wrap(err, "source package accept")
		}
		return isAccepted, nil
	case PackageTypeLanguage:
		if query.Language == nil {
			return false, errors.New("query is not set for Language Package")
		}
		isAccepted, err := p.Language.Accept(*query.Language)
		if err != nil {
			return false, errors.Wrap(err, "language package accept")
		}
		return isAccepted, nil
	default:
		// Out of vocabulary — unset, or a value from a newer
		// vuls-data-update — is unevaluable: report it as a non-fatal
		// *warning.UnevaluableError so the criterion layer can record it.
		if !p.Type.Known() {
			return false, &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluablePackageType, Cause: string(p.Type)}}
		}
		// In the vocabulary but not dispatched above: the vocabulary and
		// this switch are out of sync within this build — a bug, not newer
		// data. Fail loudly (mirrors the criteria operator default).
		return false, errors.Errorf("unexpected package type. expected: %q, actual: %q", PackageTypes(), p.Type)
	}
}
