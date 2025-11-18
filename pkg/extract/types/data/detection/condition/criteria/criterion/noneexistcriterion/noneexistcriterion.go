package noneexistcriterion

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/pkg/errors"

	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/source"
)

type PackageType int

const (
	_ PackageType = iota
	PackageTypeBinary
	PackageTypeSource

	PackageTypeUnknown
)

func (t PackageType) String() string {
	switch t {
	case PackageTypeBinary:
		return "binary"
	case PackageTypeSource:
		return "source"
	default:
		return "unknown"
	}
}

func (t PackageType) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(t.String()))
}

func (t *PackageType) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	token, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if token.Kind() != '"' {
		return fmt.Errorf("unexpected type. expected: %s, got %s", "string", token.Kind())
	}

	switch token.String() {
	case "binary":
		*t = PackageTypeBinary
	case "source":
		*t = PackageTypeSource
	case "unknown":
		*t = PackageTypeUnknown
	default:
		return fmt.Errorf("invalid PackageType %s", token.String())
	}
	return nil
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
	case "unknown":
		pt = PackageTypeUnknown
	default:
		return fmt.Errorf("invalid PackageType %s", s)
	}
	*t = pt
	return nil
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

func (c Criterion) Accept(query Query) (bool, error) {
	switch c.Type {
	case PackageTypeBinary:
		if len(query.Binaries) == 0 {
			return false, errors.New("query is not set for Binary Package")
		}
		for _, q := range query.Binaries {
			isAccepted, err := c.Binary.Accept(q)
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
			isAccepted, err := c.Source.Accept(q)
			if err != nil {
				return false, errors.Wrap(err, "source package accept")
			}
			if isAccepted {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, errors.Errorf("unexpected none exist criterion type. expected: %q, actual: %q", []PackageType{PackageTypeBinary, PackageTypeSource}, c.Type)
	}
}
