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
	debianOval "github.com/MaineK00n/vuls-data-update/pkg/build/os/debian/oval"
	debianTracker "github.com/MaineK00n/vuls-data-update/pkg/build/os/debian/tracker"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/freebsd"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/oracle"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/redhat"
	redhatOval "github.com/MaineK00n/vuls-data-update/pkg/build/os/redhat/oval"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/epss"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/exploit"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/jvn"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/kev"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/mitre"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/msf"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/nvd"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
)

var (
	supports = []string{
		"mitre", "nvd", "jvn", "epss", "msf", "exploit", "kev", "cwe", "capec", "attack",
		"alma", "alpine", "amazon", "arch", "debian", "debian-oval", "debian-tracker", "epel", "fedora", "freebsd", "gentoo", "oracle", "redhat", "redhat-api", "redhat-oval", "rocky", "suse", "suse-cvrf", "suse-oval", "ubuntu", "ubuntu-oval", "ubuntu-tracker", "windows",
		"cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems",
	}
)

func NewCmdBuild() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "build [name]",
		Short:     "Build data source",
		Args:      cobra.MatchAll(cobra.MinimumNArgs(0), cobra.OnlyValidArgs),
		ValidArgs: supports,
		RunE: func(_ *cobra.Command, args []string) error {
			var as []string

			m := map[string]bool{"cwe": false, "capec": false, "attack": false}
			for _, a := range args {
				if _, ok := m[a]; ok {
					m[a] = true
					continue
				}
				as = append(as, a)
			}
			for _, k := range []string{"cwe", "capec", "attack"} {
				if m[k] {
					as = append(as, k)
				}
			}
			if len(as) == 0 {
				as = supports
			}
			return build(as)
		},
		Example: heredoc.Doc(`
			$ vuls-data-update build
			$ vuls-data-update build nvd ubuntu
		`),
	}
	return cmd
}

func build(names []string) error {
	if err := os.RemoveAll(filepath.Join(util.DestDir(), "vulnerability")); err != nil {
		return errors.Wrapf(err, "remove %s", filepath.Join(util.DestDir(), "vulnerability"))
	}

	for _, name := range names {
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
		case "debian-oval":
			if err := debianOval.Build(); err != nil {
				return errors.Wrap(err, "failed to build debian oval")
			}
		case "debian-tracker":
			if err := debianTracker.Build(); err != nil {
				return errors.Wrap(err, "failed to build debian security tracker")
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
			if err := freebsd.Build(); err != nil {
				return errors.Wrap(err, "failed to build freebsd")
			}
		case "gentoo":
			// if err := gentoo.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build gentoo")
			// }
		case "oracle":
			if err := oracle.Build(); err != nil {
				return errors.Wrap(err, "failed to build oracle")
			}
		case "redhat":
			if err := redhat.Build(); err != nil {
				return errors.Wrap(err, "failed to build redhat")
			}
		case "redhat-api":
			// if err := redhatAPI.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build redhat api")
			// }
		case "redhat-oval":
			if err := redhatOval.Build(); err != nil {
				return errors.Wrap(err, "failed to build redhat oval")
			}
		case "rocky":
			// if err := rocky.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build rocky")
			// }
		case "suse":
			// if err := suse.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build suse")
			// }
		case "suse-cvrf":
			// if err := suseCvrf.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build suse")
			// }
		case "suse-oval":
			// if err := suseOval.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build suse")
			// }
		case "ubuntu":
			// if err := ubuntu.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build ubuntu")
			// }
		case "ubuntu-oval":
			// if err := ubuntuOval.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build ubuntu")
			// }
		case "ubuntu-tracker":
			// if err := ubuntuTracker.Build(); err != nil {
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
			return fmt.Errorf("accepts %q, received %q", supports, name)
		}
	}
	return nil
}
