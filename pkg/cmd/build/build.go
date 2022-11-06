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
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/suse"
	suseCvrf "github.com/MaineK00n/vuls-data-update/pkg/build/os/suse/cvrf"
	suseOval "github.com/MaineK00n/vuls-data-update/pkg/build/os/suse/oval"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/ubuntu"
	ubuntuOval "github.com/MaineK00n/vuls-data-update/pkg/build/os/ubuntu/oval"
	ubuntuTracker "github.com/MaineK00n/vuls-data-update/pkg/build/os/ubuntu/tracker"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/epss"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/exploit"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/jvn"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/kev"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/mitre"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/msf"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/nvd"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
)

type options struct {
	srcDir  string
	destDir string
}

var (
	supports = []string{
		"mitre", "nvd", "jvn", "", "msf", "exploit", "kev", "cwe", "capec", "attack",
		"alma", "alpine", "amazon", "arch", "debian", "debian-oval", "debian-tracker", "epel", "fedora", "freebsd", "gentoo", "oracle", "redhat", "redhat-api", "redhat-oval", "rocky", "suse", "suse-cvrf", "suse-oval", "ubuntu", "ubuntu-oval", "ubuntu-tracker", "windows",
		"cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems",
	}
)

func NewCmdBuild() *cobra.Command {
	options := &options{
		srcDir:  util.SourceDir(),
		destDir: util.DestDir(),
	}

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
			return build(as, options)
		},
		Example: heredoc.Doc(`
			$ vuls-data-update build
			$ vuls-data-update build nvd ubuntu
		`),
	}

	cmd.Flags().StringVarP(&options.srcDir, "source-dir", "s", util.SourceDir(), "directory where fetch results are located")
	cmd.Flags().StringVarP(&options.destDir, "destination-dir", "d", util.DestDir(), "output build results to specified directory")

	return cmd
}

func build(names []string, opts *options) error {
	if err := os.RemoveAll(filepath.Join(opts.destDir, "vulnerability")); err != nil {
		return errors.Wrapf(err, "remove %s", filepath.Join(opts.destDir, "vulnerability"))
	}

	for _, name := range names {
		switch name {
		case "attack":
			// if err := attack.Build(attack.WithSrcDir(filepath.Join(opts.srcDir, "attack")), attack.WithDestDir(filepath.Join(opts.destDir, "vulnerability"))); err != nil {
			// 	return errors.Wrap(err, "failed to build attack")
			// }
		case "capec":
			// if err := capec.Build(capec.WithSrcDir(filepath.Join(opts.srcDir, "capec")), capec.WithDestDir(filepath.Join(opts.destDir, "vulnerability"))); err != nil {
			// 	return errors.Wrap(err, "failed to build capec")
			// }
		case "cwe":
			// if err := cwe.Build(cwe.WithSrcDir(filepath.Join(opts.srcDir, "cwe")), cwe.WithDestDir(filepath.Join(opts.destDir, "vulnerability"))); err != nil {
			// 	return errors.Wrap(err, "failed to build cwe")
			// }
		case "epss":
			if err := epss.Build(epss.WithSrcDir(filepath.Join(opts.srcDir, "epss")), epss.WithDestDir(filepath.Join(opts.destDir, "vulnerability"))); err != nil {
				return errors.Wrap(err, "failed to build epss")
			}
		case "exploit":
			if err := exploit.Build(exploit.WithSrcDir(filepath.Join(opts.srcDir, "exploit")), exploit.WithDestDir(filepath.Join(opts.destDir, "vulnerability"))); err != nil {
				return errors.Wrap(err, "failed to build exploit")
			}
		case "jvn":
			if err := jvn.Build(jvn.WithSrcDir(filepath.Join(opts.srcDir, "jvn")), jvn.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), jvn.WithDestDetectDir(filepath.Join(opts.destDir, "cpe", "jvn"))); err != nil {
				return errors.Wrap(err, "failed to build jvn")
			}
		case "kev":
			if err := kev.Build(kev.WithSrcDir(filepath.Join(opts.srcDir, "kev")), kev.WithDestDir(filepath.Join(opts.destDir, "vulnerability"))); err != nil {
				return errors.Wrap(err, "failed to build kev")
			}
		case "mitre":
			if err := mitre.Build(mitre.WithSrcDir(filepath.Join(opts.srcDir, "mitre")), mitre.WithDestDir(filepath.Join(opts.destDir, "vulnerability"))); err != nil {
				return errors.Wrap(err, "failed to build mitre")
			}
		case "msf":
			if err := msf.Build(msf.WithSrcDir(filepath.Join(opts.srcDir, "msf")), msf.WithDestDir(filepath.Join(opts.destDir, "vulnerability"))); err != nil {
				return errors.Wrap(err, "failed to build msf")
			}
		case "nvd":
			if err := nvd.Build(nvd.WithSrcDir(filepath.Join(opts.srcDir, "nvd")), nvd.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), nvd.WithDestDetectDir(filepath.Join(opts.destDir, "cpe", "nvd"))); err != nil {
				return errors.Wrap(err, "failed to build nvd")
			}

		// os
		case "alma":
			if err := alma.Build(alma.WithSrcDir(filepath.Join(opts.srcDir, "alma")), alma.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), alma.WithDestDetectDir(filepath.Join(opts.destDir, "os", "alma"))); err != nil {
				return errors.Wrap(err, "failed to build alma")
			}
		case "alpine":
			if err := alpine.Build(alpine.WithSrcDir(filepath.Join(opts.srcDir, "alpine")), alpine.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), alpine.WithDestDetectDir(filepath.Join(opts.destDir, "os", "alpine"))); err != nil {
				return errors.Wrap(err, "failed to build alpine")
			}
		case "amazon":
			if err := amazon.Build(amazon.WithSrcDir(filepath.Join(opts.srcDir, "amazon")), amazon.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), amazon.WithDestDetectDir(filepath.Join(opts.destDir, "os", "amazon"))); err != nil {
				return errors.Wrap(err, "failed to build amazon")
			}
		case "arch":
			if err := arch.Build(arch.WithSrcDir(filepath.Join(opts.srcDir, "arch")), arch.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), arch.WithDestDetectDir(filepath.Join(opts.destDir, "os", "arch"))); err != nil {
				return errors.Wrap(err, "failed to build arch")
			}
		case "debian":
			if err := debian.Build(debian.WithSrcDir(filepath.Join(opts.srcDir, "debian")), debian.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), debian.WithDestDetectDir(filepath.Join(opts.destDir, "os", "debian"))); err != nil {
				return errors.Wrap(err, "failed to build debian")
			}
		case "debian-oval":
			if err := debianOval.Build(debianOval.WithSrcDir(filepath.Join(opts.srcDir, "debian", "oval")), debianOval.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), debianOval.WithDestDetectDir(filepath.Join(opts.destDir, "os", "debian", "oval"))); err != nil {
				return errors.Wrap(err, "failed to build debian oval")
			}
		case "debian-tracker":
			if err := debianTracker.Build(debianTracker.WithSrcDir(filepath.Join(opts.srcDir, "debian", "tracker")), debianTracker.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), debianTracker.WithDestDetectDir(filepath.Join(opts.destDir, "os", "debian", "tracker"))); err != nil {
				return errors.Wrap(err, "failed to build debian security tracker")
			}
		case "epel":
			// if err := epel.Build(epel.WithSrcDir(filepath.Join(opts.srcDir, "epel")), epel.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), epel.WithDestDetectDir(filepath.Join(opts.destDir, "os", "epel"))); err != nil {
			// 	return errors.Wrap(err, "failed to build epel")
			// }
		case "fedora":
			// if err := fedora.Build(fedora.WithSrcDir(filepath.Join(opts.srcDir, "fedora")), fedora.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), fedora.WithDestDetectDir(filepath.Join(opts.destDir, "os", "fedora"))); err != nil {
			// 	return errors.Wrap(err, "failed to build fedora")
			// }
		case "freebsd":
			if err := freebsd.Build(freebsd.WithSrcDir(filepath.Join(opts.srcDir, "freebsd")), freebsd.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), freebsd.WithDestDetectDir(filepath.Join(opts.destDir, "os", "freebsd"))); err != nil {
				return errors.Wrap(err, "failed to build freebsd")
			}
		case "gentoo":
			// if err := gentoo.Build(gentoo.WithSrcDir(filepath.Join(opts.srcDir, "gentoo")), gentoo.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), gentoo.WithDestDetectDir(filepath.Join(opts.destDir, "os", "gentoo"))); err != nil {
			// 	return errors.Wrap(err, "failed to build gentoo")
			// }
		case "oracle":
			if err := oracle.Build(oracle.WithSrcDir(filepath.Join(opts.srcDir, "oracle")), oracle.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), oracle.WithDestDetectDir(filepath.Join(opts.destDir, "os", "oracle"))); err != nil {
				return errors.Wrap(err, "failed to build oracle")
			}
		case "redhat":
			if err := redhat.Build(redhat.WithSrcDir(filepath.Join(opts.srcDir, "redhat")), redhat.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), redhat.WithDestDetectDir(filepath.Join(opts.destDir, "os", "redhat"))); err != nil {
				return errors.Wrap(err, "failed to build redhat")
			}
		case "redhat-api":
			// if err := redhatAPI.Build(redhatAPI.WithSrcDir(filepath.Join(opts.srcDir, "redhat", "api")), redhatAPI.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), redhatAPI.WithDestDetectDir(filepath.Join(opts.destDir, "os", "redhat", "api"))); err != nil {
			// 	return errors.Wrap(err, "failed to build redhat api")
			// }
		case "redhat-oval":
			if err := redhatOval.Build(redhatOval.WithSrcDir(filepath.Join(opts.srcDir, "redhat", "oval")), redhatOval.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), redhatOval.WithDestDetectDir(filepath.Join(opts.destDir, "os", "oval"))); err != nil {
				return errors.Wrap(err, "failed to build redhat oval")
			}
		case "rocky":
			// if err := rocky.Build(rocky.WithSrcDir(filepath.Join(opts.srcDir, "rocky")), rocky.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), rocky.WithDestDetectDir(filepath.Join(opts.destDir, "os", "rocky"))); err != nil {
			// 	return errors.Wrap(err, "failed to build rocky")
			// }
		case "suse":
			if err := suse.Build(suse.WithSrcDir(filepath.Join(opts.srcDir, "suse")), suse.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), suse.WithDestDetectDir(filepath.Join(opts.destDir, "os", "suse"))); err != nil {
				return errors.Wrap(err, "failed to build suse")
			}
		case "suse-cvrf":
			if err := suseCvrf.Build(suseCvrf.WithSrcDir(filepath.Join(opts.srcDir, "suse", "cvrf")), suseCvrf.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), suseCvrf.WithDestDetectDir(filepath.Join(opts.destDir, "os", "suse", "cvrf"))); err != nil {
				return errors.Wrap(err, "failed to build suse cvrf")
			}
		case "suse-oval":
			if err := suseOval.Build(suseOval.WithSrcDir(filepath.Join(opts.srcDir, "suse", "oval")), suseOval.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), suseOval.WithDestDetectDir(filepath.Join(opts.destDir, "os", "suse", "oval"))); err != nil {
				return errors.Wrap(err, "failed to build suse oval")
			}
		case "ubuntu":
			if err := ubuntu.Build(ubuntu.WithSrcDir(filepath.Join(opts.srcDir, "ubuntu")), ubuntu.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), ubuntu.WithDestDetectDir(filepath.Join(opts.destDir, "os", "ubuntu"))); err != nil {
				return errors.Wrap(err, "failed to build ubuntu")
			}
		case "ubuntu-oval":
			if err := ubuntuOval.Build(ubuntuOval.WithSrcDir(filepath.Join(opts.srcDir, "ubuntu", "oval")), ubuntuOval.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), ubuntuOval.WithDestDetectDir(filepath.Join(opts.destDir, "os", "ubuntu", "oval"))); err != nil {
				return errors.Wrap(err, "failed to build ubuntu oval")
			}
		case "ubuntu-tracker":
			if err := ubuntuTracker.Build(ubuntuTracker.WithSrcDir(filepath.Join(opts.srcDir, "ubuntu", "tracker")), ubuntuTracker.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), ubuntuTracker.WithDestDetectDir(filepath.Join(opts.destDir, "os", "ubuntu", "tracker"))); err != nil {
				return errors.Wrap(err, "failed to build ubuntu security tracker")
			}
		case "windows":
			// if err := windows.Build(windows.WithSrcDir(filepath.Join(opts.srcDir, "windows")), windows.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), windows.WithDestDetectDir(filepath.Join(opts.destDir, "os", "windows"))); err != nil {
			// 	return errors.Wrap(err, "failed to build windows")
			// }

		// library
		case "cargo":
			// if err := cargo.Build(cargo.WithSrcDir(filepath.Join(opts.srcDir, "cargo")), cargo.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), cargo.WithDestDetectDir(filepath.Join(opts.destDir, "library", "cargo"))); err != nil {
			// 	return errors.Wrap(err, "failed to build cargo")
			// }
		case "composer":
			// if err := composer.Build(composer.WithSrcDir(filepath.Join(opts.srcDir, "composer")), composer.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), composer.WithDestDetectDir(filepath.Join(opts.destDir, "library", "composer"))); err != nil {
			// 	return errors.Wrap(err, "failed to build composer")
			// }
		case "conan":
			// if err := conan.Build(conan.WithSrcDir(filepath.Join(opts.srcDir, "conan")), conan.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), conan.WithDestDetectDir(filepath.Join(opts.destDir, "library", "conan"))); err != nil {
			// 	return errors.Wrap(err, "failed to build conan")
			// }
		case "erlang":
			// if err := erlang.Build(erlang.WithSrcDir(filepath.Join(opts.srcDir, "erlang")), erlang.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), erlang.WithDestDetectDir(filepath.Join(opts.destDir, "library", "erlang"))); err != nil {
			// 	return errors.Wrap(err, "failed to build erlang")
			// }
		case "golang":
			// if err := golang.Build(golang.WithSrcDir(filepath.Join(opts.srcDir, "golang")), golang.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), golang.WithDestDetectDir(filepath.Join(opts.destDir, "library", "golang"))); err != nil {
			// 	return errors.Wrap(err, "failed to build golang")
			// }
		case "maven":
			// if err := maven.Build(maven.WithSrcDir(filepath.Join(opts.srcDir, "maven")), maven.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), maven.WithDestDetectDir(filepath.Join(opts.destDir, "library", "maven"))); err != nil {
			// 	return errors.Wrap(err, "failed to build maven")
			// }
		case "npm":
			// if err := npm.Build(npm.WithSrcDir(filepath.Join(opts.srcDir, "npm")), npm.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), npm.WithDestDetectDir(filepath.Join(opts.destDir, "library", "npm"))); err != nil {
			// 	return errors.Wrap(err, "failed to build npm")
			// }
		case "nuget":
			// if err := nuget.Build(nuget.WithSrcDir(filepath.Join(opts.srcDir, "nuget")), nuget.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), nuget.WithDestDetectDir(filepath.Join(opts.destDir, "library", "nuget"))); err != nil {
			// 	return errors.Wrap(err, "failed to build nuget")
			// }
		case "pip":
			// if err := pip.Build(pip.WithSrcDir(filepath.Join(opts.srcDir, "pip")), pip.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), pip.WithDestDetectDir(filepath.Join(opts.destDir, "library", "pip"))); err != nil {
			// 	return errors.Wrap(err, "failed to build pip")
			// }
		case "rubygems":
			// if err := rubygems.Build(rubygems.WithSrcDir(filepath.Join(opts.srcDir, "rubygems")), rubygems.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), rubygems.WithDestDetectDir(filepath.Join(opts.destDir, "library", "rubygems"))); err != nil {
			// 	return errors.Wrap(err, "failed to build rubygems")
			// }
		default:
			return fmt.Errorf("accepts %q, received %q", supports, name)
		}
	}
	return nil
}
