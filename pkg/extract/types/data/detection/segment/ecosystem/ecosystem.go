package ecosystem

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

type Ecosystem string

const (
	EcosystemTypeAlma        = "alma"
	EcosystemTypeAlpine      = "alpine"
	EcosystemTypeAmazon      = "amazon"
	EcosystemTypeArch        = "arch"
	EcosytemCentOS           = "centos"
	EcosystemTypeDebian      = "debian"
	EcosystemTypeEPEL        = "epel"
	EcosystemTypeEPELNext    = "epel-next"
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
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeAlpine:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return "", errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem(fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])), nil
	case EcosystemTypeAmazon:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeArch:
		return Ecosystem(family), nil
	case EcosytemCentOS:
		return Ecosystem(fmt.Sprintf("%s:%s", EcosystemTypeRedHat, strings.Split(release, ".")[0])), nil
	case EcosystemTypeDebian:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeEPEL:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeEPELNext:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeFedora:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeFreeBSD:
		return Ecosystem(family), nil
	case EcosystemTypeGentoo:
		return Ecosystem(family), nil
	case EcosystemTypeNetBSD:
		return Ecosystem(family), nil
	case EcosystemTypeOracle:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeRedHat:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeRocky:
		return Ecosystem(fmt.Sprintf("%s:%s", family, strings.Split(release, ".")[0])), nil
	case EcosystemTypeOpenSUSE:
		if release == "tumbleweed" {
			return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
		}
		if strings.HasPrefix(release, "leap:") {
			ss := strings.Split(strings.TrimPrefix(release, "leap:"), ".")
			if len(ss) < 2 {
				return "", errors.Errorf("unexpected release format. expected: %q, actual: %q", "leap:<major>.<minor>(.<patch>)", release)
			}
			return Ecosystem(fmt.Sprintf("%s-leap:%s.%s", family, ss[0], ss[1])), nil
		}
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return "", errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem(fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])), nil
	case EcosystemTypeSUSEServer:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return "", errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem(fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])), nil
	case EcosystemTypeSUSEDesktop:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return "", errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem(fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])), nil
	case EcosystemTypeUbuntu:
		ss := strings.Split(release, ".")
		if len(ss) < 2 {
			return "", errors.Errorf("unexpected release format. expected: %q, actual: %q", "<major>.<minor>(.<patch>)", release)
		}
		return Ecosystem(fmt.Sprintf("%s:%s.%s", family, ss[0], ss[1])), nil
	case EcosystemTypeWindows:
		return Ecosystem(fmt.Sprintf("%s:%s", family, release)), nil
	case EcosystemTypeCPE:
		return Ecosystem(family), nil
	case EcosystemTypeFortinet:
		return Ecosystem(family), nil
	case EcosystemTypeCargo:
		return Ecosystem(family), nil
	case EcosystemTypeComposer:
		return Ecosystem(family), nil
	case EcosystemTypeConan:
		return Ecosystem(family), nil
	case EcosystemTypeErlang:
		return Ecosystem(family), nil
	case EcosystemTypeGolang:
		return Ecosystem(family), nil
	case EcosystemTypeHaskell:
		return Ecosystem(family), nil
	case EcosystemTypeMaven:
		return Ecosystem(family), nil
	case EcosystemTypeNpm:
		return Ecosystem(family), nil
	case EcosystemTypeNuget:
		return Ecosystem(family), nil
	case EcosystemTypePerl:
		return Ecosystem(family), nil
	case EcosystemTypePip:
		return Ecosystem(family), nil
	case EcosystemTypePub:
		return Ecosystem(family), nil
	case EcosystemTypeR:
		return Ecosystem(family), nil
	case EcosystemTypeRubygems:
		return Ecosystem(family), nil
	case EcosystemTypeSwift:
		return Ecosystem(family), nil
	default:
		return "", errors.Errorf("unexpected family. expected: %q, actual: %q", []Ecosystem{EcosystemTypeAlma, EcosystemTypeAlpine, EcosystemTypeAmazon, EcosystemTypeArch, EcosytemCentOS, EcosystemTypeDebian, EcosystemTypeEPEL, EcosystemTypeFedora, EcosystemTypeFreeBSD, EcosystemTypeGentoo, EcosystemTypeNetBSD, EcosystemTypeOracle, EcosystemTypeRedHat, EcosystemTypeRocky, EcosystemTypeOpenSUSE, EcosystemTypeSUSEServer, EcosystemTypeSUSEDesktop, EcosystemTypeUbuntu, EcosystemTypeWindows, EcosystemTypeCPE, EcosystemTypeFortinet, EcosystemTypeCargo, EcosystemTypeComposer, EcosystemTypeConan, EcosystemTypeErlang, EcosystemTypeGolang, EcosystemTypeHaskell, EcosystemTypeMaven, EcosystemTypeNpm, EcosystemTypeNuget, EcosystemTypePerl, EcosystemTypePip, EcosystemTypePub, EcosystemTypeR, EcosystemTypeRubygems, EcosystemTypeSwift}, family)
	}
}
