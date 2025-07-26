package criterionpackage

import (
	"cmp"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	cpeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	languageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/language"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
)

type PackageType int

const (
	_ PackageType = iota
	PackageTypeBinary
	PackageTypeSource
	PackageTypeCPE
	PackageTypeLanguage

	PackageTypeUnknown
)

func (t PackageType) String() string {
	switch t {
	case PackageTypeBinary:
		return "binary"
	case PackageTypeSource:
		return "source"
	case PackageTypeCPE:
		return "cpe"
	case PackageTypeLanguage:
		return "language"
	default:
		return "unknown"
	}
}

func (t PackageType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *PackageType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var pt PackageType
	switch s {
	case "binary":
		pt = PackageTypeBinary
	case "source":
		pt = PackageTypeSource
	case "cpe":
		pt = PackageTypeCPE
	case "language":
		pt = PackageTypeLanguage
	case "unknown":
		pt = PackageTypeUnknown
	default:
		return fmt.Errorf("invalid PackageType %s", s)
	}
	*t = pt
	return nil
}

type Package struct {
	Type     PackageType            `json:"type,omitempty"`
	Binary   *binaryTypes.Package   `json:"binary,omitempty"`
	Source   *sourceTypes.Package   `json:"source,omitempty"`
	CPE      *cpeTypes.CPE          `json:"cpe,omitempty"`
	Language *languageTypes.Package `json:"language,omitempty"`
}

func (p *Package) Sort() {
	switch p.Type {
	case PackageTypeBinary:
		p.Binary.Sort()
	case PackageTypeSource:
		p.Source.Sort()
	case PackageTypeCPE:
	case PackageTypeLanguage:
		p.Language.Sort()
	default:
	}
}

func Compare(x, y Package) int {
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
			case PackageTypeCPE:
				switch {
				case x.CPE == nil && y.CPE == nil:
					return 0
				case x.CPE == nil && y.CPE != nil:
					return -1
				case x.CPE != nil && y.CPE == nil:
					return +1
				default:
					return cmp.Compare(*x.CPE, *y.CPE)
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
	CPE      *cpeTypes.Query
	Language *languageTypes.Query
}

func (p Package) Accept(query Query) (bool, error) {
	switch p.Type {
	case PackageTypeBinary:
		if query.Binary == nil {
			return false, errors.New("query is not set for Binary Package")
		}
		isAccepted, err := p.Binary.Accept(*query.Binary)
		if err != nil {
			return false, errors.Wrap(err, "binary package accept")
		}
		return isAccepted, nil
	case PackageTypeSource:
		if query.Source == nil {
			return false, errors.New("query is not set for Source Package")
		}
		isAccepted, err := p.Source.Accept(*query.Source)
		if err != nil {
			return false, errors.Wrap(err, "source package accept")
		}
		return isAccepted, nil
	case PackageTypeCPE:
		if query.CPE == nil {
			return false, errors.New("query is not set for CPE")
		}
		isAccepted, err := p.CPE.Accept(*query.CPE)
		if err != nil {
			return false, errors.Wrap(err, "cpe accept")
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
		return false, errors.Errorf("unexpected package type. expected: %q, actual: %q", []PackageType{PackageTypeBinary, PackageTypeSource, PackageTypeCPE, PackageTypeLanguage}, p.Type)
	}
}
