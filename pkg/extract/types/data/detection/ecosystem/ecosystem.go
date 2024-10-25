package ecosystem

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

type Ecosystem struct {
	Family string `json:"family,omitempty"`
	Branch string `json:"branch,omitempty"`
}

const (
	EcosystemTypeAlma        = "alma"
	EcosystemTypeAlpine      = "alpine"
	EcosystemTypeAmazon      = "amazon"
	EcosystemTypeArch        = "arch"
	EcosystemTypeDebian      = "debian"
	EcosystemTypeEPEL        = "epel"
	EcosystemTypeFedora      = "fedora"
	EcosystemTypeFreeBSD     = "freebsd"
	EcosystemTypeGentoo      = "gentoo"
	EcosystemTypeNetBSD      = "netbsd"
	EcosystemTypeOracle      = "oracle"
	EcosystemTypeRedHat      = "redhat"
	EcosystemTypeRocky       = "rocky"
	EcosystemTypeOpenSUSE    = "opensuse"
	EcosystemTypeSUSEServer  = "sles"
	EcosystemTypeSUSEDesktop = "sled"
	EcosystemTypeUbuntu      = "ubuntu"
	EcosystemTypeWindows     = "windows"

	EcosystemTypeCPE = "cpe"

	EcosystemTypeFortinet = "fortinet"

	EcosystemTypeCargo    = "cargo"
	EcosystemTypeComposer = "composer"
	EcosystemTypeConan    = "conan"
	EcosystemTypeErlang   = "erlang"
	EcosystemTypeGolang   = "golang"
	EcosystemTypeHaskell  = "haskell"
	EcosystemTypeMaven    = "maven"
	EcosystemTypeNpm      = "npm"
	EcosystemTypeNuget    = "nuget"
	EcosystemTypePerl     = "perl"
	EcosystemTypePip      = "pip"
	EcosystemTypePub      = "pub"
	EcosystemTypeR        = "r"
	EcosystemTypeRubygems = "rubygems"
	EcosystemTypeSwift    = "swift"
)

func GetEcosystem(family, release string) (Ecosystem, error) {
	switch family {
	case EcosystemTypeAlma:
		return Ecosystem{Family: fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])}, nil
	case EcosystemTypeAlpine:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return Ecosystem{}, errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem{Family: fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])}, nil
	case EcosystemTypeAmazon:
		return Ecosystem{Family: fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])}, nil
	case EcosystemTypeArch:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeDebian:
		return Ecosystem{Family: fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])}, nil
	case EcosystemTypeEPEL:
		return Ecosystem{Family: fmt.Sprintf("%s:%s", family, release)}, nil
	case EcosystemTypeFedora:
		return Ecosystem{Family: fmt.Sprintf("%s:%s", family, release)}, nil
	case EcosystemTypeFreeBSD:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeGentoo:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeNetBSD:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeOracle:
		return Ecosystem{Family: fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])}, nil
	case EcosystemTypeRedHat:
		return Ecosystem{Family: fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])}, nil
	case EcosystemTypeRocky:
		return Ecosystem{Family: fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])}, nil
	case EcosystemTypeOpenSUSE:
		if release == "tumbleweed" {
			return Ecosystem{Family: fmt.Sprintf("%s:%s", family, release)}, nil
		}
		if strings.HasPrefix(release, "leap:") {
			ss := strings.Split(strings.TrimPrefix(release, "leap:"), ".")
			if len(ss) < 2 {
				return Ecosystem{}, errors.Errorf("unexpected release format. expected: %q, actual: %q", "leap:<major>.<minor>(.<patch>)", release)
			}
			return Ecosystem{Family: fmt.Sprintf("%s-leap:%s.%s", family, ss[0], ss[1])}, nil
		}
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return Ecosystem{}, errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem{Family: fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])}, nil
	case EcosystemTypeSUSEServer:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return Ecosystem{}, errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem{Family: fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])}, nil
	case EcosystemTypeSUSEDesktop:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return Ecosystem{}, errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem{Family: fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])}, nil
	case EcosystemTypeUbuntu:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return Ecosystem{}, errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem{Family: fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])}, nil
	case EcosystemTypeWindows:
		return Ecosystem{Family: fmt.Sprintf("%s:%s", family, release)}, nil
	case EcosystemTypeCPE:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeFortinet:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeCargo:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeComposer:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeConan:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeErlang:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeGolang:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeHaskell:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeMaven:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeNpm:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeNuget:
		return Ecosystem{Family: family}, nil
	case EcosystemTypePerl:
		return Ecosystem{Family: family}, nil
	case EcosystemTypePip:
		return Ecosystem{Family: family}, nil
	case EcosystemTypePub:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeR:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeRubygems:
		return Ecosystem{Family: family}, nil
	case EcosystemTypeSwift:
		return Ecosystem{Family: family}, nil
	default:
		return Ecosystem{}, errors.Errorf("unexpected family. expected: %q, actual: %q", []string{EcosystemTypeAlma, EcosystemTypeAlpine, EcosystemTypeAmazon, EcosystemTypeArch, EcosystemTypeDebian, EcosystemTypeEPEL, EcosystemTypeFedora, EcosystemTypeFreeBSD, EcosystemTypeGentoo, EcosystemTypeNetBSD, EcosystemTypeOracle, EcosystemTypeRedHat, EcosystemTypeRocky, EcosystemTypeOpenSUSE, EcosystemTypeSUSEServer, EcosystemTypeSUSEDesktop, EcosystemTypeUbuntu, EcosystemTypeWindows, EcosystemTypeCPE, EcosystemTypeFortinet, EcosystemTypeCargo, EcosystemTypeComposer, EcosystemTypeConan, EcosystemTypeErlang, EcosystemTypeGolang, EcosystemTypeHaskell, EcosystemTypeMaven, EcosystemTypeNpm, EcosystemTypeNuget, EcosystemTypePerl, EcosystemTypePip, EcosystemTypePub, EcosystemTypeR, EcosystemTypeRubygems, EcosystemTypeSwift}, family)
	}
}

func Compare(x, y Ecosystem) int {
	return cmp.Or(
		cmp.Compare(x.Family, y.Family),
		cmp.Compare(x.Branch, y.Branch),
	)
}
