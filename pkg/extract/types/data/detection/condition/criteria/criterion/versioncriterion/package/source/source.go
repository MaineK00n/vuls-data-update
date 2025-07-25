package source

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

type Package struct {
	Name         string   `json:"name,omitempty"`
	Repositories []string `json:"repositories,omitempty"`
}

func (p *Package) Sort() {
	slices.Sort(p.Repositories)
}

func Compare(x, y Package) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		slices.Compare(x.Repositories, y.Repositories),
	)
}

type Query struct {
	Name       string
	Repository string
}

func (p Package) Accept(family ecosystemTypes.Ecosystem, query Query) (bool, error) {
	n1 := query.Name
	if isKernelPackage(family, query.Name) {
		n1 = rename(family, query.Name)
	}

	n2 := p.Name
	if isKernelPackage(family, p.Name) {
		n2 = rename(family, p.Name)
	}

	if n1 != n2 {
		return false, nil
	}

	if query.Repository != "" && len(p.Repositories) > 0 && !slices.Contains(p.Repositories, query.Repository) {
		return false, nil
	}

	return true, nil
}

func rename(family ecosystemTypes.Ecosystem, name string) string {
	switch family {
	case ecosystemTypes.EcosystemTypeDebian:
		return strings.NewReplacer("linux-signed", "linux", "linux-latest", "linux", "-amd64", "", "-arm64", "", "-i386", "").Replace(name)
	case ecosystemTypes.EcosystemTypeUbuntu:
		return strings.NewReplacer("linux-signed", "linux", "linux-meta", "linux").Replace(name)
	default:
		return name
	}
}

func isKernelPackage(family ecosystemTypes.Ecosystem, name string) bool {
	switch family {
	case ecosystemTypes.EcosystemTypeDebian:
		switch ss := strings.Split(rename(family, name), "-"); len(ss) {
		case 1:
			return ss[0] == "linux"
		case 2:
			if ss[0] != "linux" {
				return false
			}
			switch ss[1] {
			case "grsec":
				return true
			default:
				_, err := strconv.ParseFloat(ss[1], 64)
				return err == nil
			}
		default:
			return false
		}
	case ecosystemTypes.EcosystemTypeUbuntu:
		switch ss := strings.Split(rename(family, name), "-"); len(ss) {
		case 1:
			return ss[0] == "linux"
		case 2:
			if ss[0] != "linux" {
				return false
			}
			switch ss[1] {
			case "armadaxp", "mako", "manta", "flo", "goldfish", "joule", "raspi", "raspi2", "snapdragon", "allwinner", "aws", "azure", "bluefield", "dell300x", "gcp", "gke", "gkeop", "ibm", "iot", "laptop", "lowlatency", "kvm", "nvidia", "oem", "oracle", "euclid", "hwe", "riscv", "starfive", "realtime", "mtk":
				return true
			default:
				_, err := strconv.ParseFloat(ss[1], 64)
				return err == nil
			}
		case 3:
			if ss[0] != "linux" {
				return false
			}
			switch ss[1] {
			case "ti":
				return ss[2] == "omap4"
			case "raspi", "raspi2", "allwinner", "gke", "gkeop", "ibm", "oracle", "riscv", "starfive":
				_, err := strconv.ParseFloat(ss[2], 64)
				return err == nil
			case "aws":
				switch ss[2] {
				case "hwe", "edge":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "azure":
				switch ss[2] {
				case "cvm", "fde", "edge":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "gcp":
				switch ss[2] {
				case "edge":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "intel":
				switch ss[2] {
				case "iotg", "opt":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "oem":
				switch ss[2] {
				case "osp1":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "lts":
				switch ss[2] {
				case "utopic", "vivid", "wily", "xenial":
					return true
				default:
					return false
				}
			case "hwe":
				switch ss[2] {
				case "edge":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "xilinx":
				return ss[2] == "zynqmp"
			case "nvidia":
				switch ss[2] {
				case "tegra":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			default:
				return false
			}
		case 4:
			if ss[0] != "linux" {
				return false
			}
			switch ss[1] {
			case "azure":
				if ss[2] != "fde" {
					return false
				}
				_, err := strconv.ParseFloat(ss[3], 64)
				return err == nil
			case "intel":
				if ss[2] != "iotg" {
					return false
				}
				_, err := strconv.ParseFloat(ss[3], 64)
				return err == nil
			case "lowlatency":
				if ss[2] != "hwe" {
					return false
				}
				_, err := strconv.ParseFloat(ss[3], 64)
				return err == nil
			case "nvidia":
				if ss[2] != "tegra" {
					return false
				}
				switch ss[3] {
				case "igx":
					return true
				default:
					_, err := strconv.ParseFloat(ss[3], 64)
					return err == nil
				}
			default:
				return false
			}
		default:
			return false
		}
	default:
		return false
	}
}
