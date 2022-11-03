package build

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/build/os/alma"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/alpine"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/amazon"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/arch"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/debian"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/epss"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/exploit"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/jvn"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/kev"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/mitre"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/msf"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/nvd"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
)

func NewCmdBuild() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build data source",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return build()
		},
		Example: heredoc.Doc(`
			$ vuls-data-update build
		`),
	}
	return cmd
}

func build() error {
	if err := os.RemoveAll(filepath.Join(util.DestDir(), "vulnerability")); err != nil {
		return errors.Wrapf(err, "remove %s", filepath.Join(util.DestDir(), "vulnerability"))
	}

	for _, name := range []string{
		"mitre", "nvd", "jvn", "epss", "msf", "exploit", "kev",
		"alma", "alpine", "amazon", "arch", "debian", "epel", "fedora", "freebsd", "gentoo", "oracle", "redhat", "rocky", "suse", "ubuntu", "windows",
		"cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems",
		"cwe", "capec", "attack",
	} {
		switch name {
		case "attack":
			// if err := attack.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build attack")
			// }
		case "capec":
			// if err := capec.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build capec")
			// }
		case "cwe":
			// if err := cwe.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build cwe")
			// }
		case "epss":
			if err := epss.Build(); err != nil {
				return errors.Wrap(err, "failed to build epss")
			}
		case "exploit":
			if err := exploit.Build(); err != nil {
				return errors.Wrap(err, "failed to build exploit")
			}
		case "jvn":
			if err := jvn.Build(); err != nil {
				return errors.Wrap(err, "failed to build jvn")
			}
		case "kev":
			if err := kev.Build(); err != nil {
				return errors.Wrap(err, "failed to build kev")
			}
		case "mitre":
			if err := mitre.Build(); err != nil {
				return errors.Wrap(err, "failed to build mitre")
			}
		case "msf":
			if err := msf.Build(); err != nil {
				return errors.Wrap(err, "failed to build msf")
			}
		case "nvd":
			if err := nvd.Build(); err != nil {
				return errors.Wrap(err, "failed to build nvd")
			}

		// os
		case "alma":
			if err := alma.Build(); err != nil {
				return errors.Wrap(err, "failed to build alma")
			}
		case "alpine":
			if err := alpine.Build(); err != nil {
				return errors.Wrap(err, "failed to build alpine")
			}
		case "amazon":
			if err := amazon.Build(); err != nil {
				return errors.Wrap(err, "failed to build amazon")
			}
		case "arch":
			if err := arch.Build(); err != nil {
				return errors.Wrap(err, "failed to build arch")
			}
		case "debian":
			if err := debian.Build(); err != nil {
				return errors.Wrap(err, "failed to build debian")
			}
		case "epel":
			// if err := epel.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build epel")
			// }
		case "fedora":
			// if err := fedora.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build fedora")
			// }
		case "freebsd":
			// if err := freebsd.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build freebsd")
			// }
		case "gentoo":
			// if err := gentoo.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build gentoo")
			// }
		case "oracle":
			// if err := oracle.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build oracle")
			// }
		case "redhat":
			// if err := redhat.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build redhat")
			// }
		case "rocky":
			// if err := rocky.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build rocky")
			// }
		case "suse":
			// if err := suse.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build suse")
			// }
		case "ubuntu":
			// if err := ubuntu.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build ubuntu")
			// }
		case "windows":
			// if err := windows.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build windows")
			// }

		// library
		case "cargo":
			// if err := cargo.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build cargo")
			// }
		case "composer":
			// if err := composer.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build composer")
			// }
		case "conan":
			// if err := conan.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build conan")
			// }
		case "erlang":
			// if err := erlang.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build erlang")
			// }
		case "golang":
			// if err := golang.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build golang")
			// }
		case "maven":
			// if err := maven.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build maven")
			// }
		case "npm":
			// if err := npm.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build npm")
			// }
		case "nuget":
			// if err := nuget.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build nuget")
			// }
		case "pip":
			// if err := pip.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build pip")
			// }
		case "rubygems":
			// if err := rubygems.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build rubygems")
			// }
		default:
			return fmt.Errorf("accepts %q, received %q", []string{
				"mitre", "nvd", "jvn", "epss", "msf", "exploit", "kev", "cwe", "capec", "attack",
				"alma", "alpine", "amazon", "arch", "debian", "epel", "fedora", "freebsd", "gentoo", "oracle", "redhat", "rocky", "suse", "ubuntu", "windows",
				"cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems",
			}, name)
		}
	}
	return nil
}
