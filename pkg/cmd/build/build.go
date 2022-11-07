package build

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

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
	rmVulnDir          bool
	srcDir             string
	srcCompressFormat  string
	destDir            string
	destCompressFormat string
}

var (
	supports = []string{
		"mitre", "nvd", "jvn", "msf", "exploit", "kev", "epss", "cwe", "capec", "attack",
		"alma", "alpine", "amazon", "arch", "debian", "epel", "fedora", "freebsd", "gentoo", "oracle", "redhat", "rocky", "suse", "ubuntu", "windows",
		"cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems",
	}
)

func NewCmdBuild() *cobra.Command {
	options := &options{
		rmVulnDir:          true,
		srcDir:             util.SourceDir(),
		srcCompressFormat:  "",
		destDir:            util.DestDir(),
		destCompressFormat: "",
	}

	cmd := &cobra.Command{
		Use:       "build [name]",
		Short:     "Build data source",
		Args:      cobra.MatchAll(cobra.MinimumNArgs(0), cobra.OnlyValidArgs),
		ValidArgs: supports,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if !slices.Contains([]string{"", "gzip", "bzip2", "xz"}, options.srcCompressFormat) {
				return errors.New(`--source-compress-format flag allows ["", "gzip", "bzip2", "xz"].`)
			}
			if !slices.Contains([]string{"", "gzip", "bzip2", "xz"}, options.destCompressFormat) {
				return errors.New(`--destination-compress-format flag allows ["", "gzip", "bzip2", "xz"].`)
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = supports
			}

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
			return build(as, options)
		},
		Example: heredoc.Doc(`
			$ vuls-data-update build
			$ vuls-data-update build nvd ubuntu
		`),
	}

	cmd.Flags().BoolVarP(&options.rmVulnDir, "rm-vuln-dir", "", true, "remove vulnerability directory at the start of the build")
	cmd.Flags().StringVarP(&options.srcDir, "source-dir", "", util.SourceDir(), "directory where fetch results are located")
	cmd.Flags().StringVarP(&options.destDir, "destination-dir", "", util.DestDir(), "output build results to specified directory")
	cmd.Flags().StringVarP(&options.srcCompressFormat, "source-compress-format", "", "", `source compression format. available: ["gzip", "bzip2", "xz"]`)
	cmd.Flags().StringVarP(&options.destCompressFormat, "destination-compress-format", "", "", `destination compression format. available: ["gzip", "bzip2", "xz"]`)

	return cmd
}

func build(names []string, opts *options) error {
	if opts.rmVulnDir {
		if err := os.RemoveAll(filepath.Join(opts.destDir, "vulnerability")); err != nil {
			return errors.Wrapf(err, "remove %s", filepath.Join(opts.destDir, "vulnerability"))
		}
	}

	for _, name := range names {
		switch name {
		case "attack":
			// if err := attack.Build(attack.Build(attack.WithSrcDir(filepath.Join(opts.srcDir, "attack")), attack.WithSrcCompressFormat(opts.srcCompressFormat), attack.WithDestDir(filepath.Join(opts.destDir, "vulnerability")), attack.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build attack")
			// }
		case "capec":
			// if err := capec.Build(capec.WithSrcDir(filepath.Join(opts.srcDir, "capec")), capec.WithSrcCompressFormat(opts.srcCompressFormat), capec.WithDestDir(filepath.Join(opts.destDir, "vulnerability")), capec.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build capec")
			// }
		case "cwe":
			// if err := cwe.Build(cwe.WithSrcDir(filepath.Join(opts.srcDir, "cwe")), cwe.WithSrcCompressFormat(opts.srcCompressFormat), cwe.WithDestDir(filepath.Join(opts.destDir, "vulnerability")), cwe.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build cwe")
			// }
		case "epss":
			if err := epss.Build(epss.WithSrcDir(filepath.Join(opts.srcDir, "epss")), epss.WithSrcCompressFormat(opts.srcCompressFormat), epss.WithDestDir(filepath.Join(opts.destDir, "vulnerability")), epss.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build epss")
			}
		case "exploit":
			if err := exploit.Build(exploit.WithSrcDir(filepath.Join(opts.srcDir, "exploit")), exploit.WithSrcCompressFormat(opts.srcCompressFormat), exploit.WithDestDir(filepath.Join(opts.destDir, "vulnerability")), exploit.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build exploit")
			}
		case "jvn":
			if err := jvn.Build(jvn.WithSrcDir(filepath.Join(opts.srcDir, "jvn")), jvn.WithSrcCompressFormat(opts.srcCompressFormat), jvn.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), jvn.WithDestDetectDir(filepath.Join(opts.destDir, "cpe", "jvn")), jvn.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build jvn")
			}
		case "kev":
			if err := kev.Build(kev.WithSrcDir(filepath.Join(opts.srcDir, "kev")), kev.WithSrcCompressFormat(opts.srcCompressFormat), kev.WithDestDir(filepath.Join(opts.destDir, "vulnerability")), kev.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build kev")
			}
		case "mitre":
			if err := mitre.Build(mitre.WithSrcDir(filepath.Join(opts.srcDir, "mitre")), mitre.WithSrcCompressFormat(opts.srcCompressFormat), mitre.WithDestDir(filepath.Join(opts.destDir, "vulnerability")), mitre.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build mitre")
			}
		case "msf":
			if err := msf.Build(msf.WithSrcDir(filepath.Join(opts.srcDir, "msf")), msf.WithSrcCompressFormat(opts.srcCompressFormat), msf.WithDestDir(filepath.Join(opts.destDir, "vulnerability")), msf.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build msf")
			}
		case "nvd":
			if err := nvd.Build(nvd.WithSrcDir(filepath.Join(opts.srcDir, "nvd")), nvd.WithSrcCompressFormat(opts.srcCompressFormat), nvd.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), nvd.WithDestDetectDir(filepath.Join(opts.destDir, "cpe", "nvd")), nvd.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build nvd")
			}

		// os
		case "alma":
			if err := alma.Build(alma.WithSrcDir(filepath.Join(opts.srcDir, "alma")), alma.WithSrcCompressFormat(opts.srcCompressFormat), alma.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), alma.WithDestDetectDir(filepath.Join(opts.destDir, "os", "alma")), alma.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build alma")
			}
		case "alpine":
			if err := alpine.Build(alpine.WithSrcDir(filepath.Join(opts.srcDir, "alpine")), alpine.WithSrcCompressFormat(opts.srcCompressFormat), alpine.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), alpine.WithDestDetectDir(filepath.Join(opts.destDir, "os", "alpine")), alpine.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build alpine")
			}
		case "amazon":
			if err := amazon.Build(amazon.WithSrcDir(filepath.Join(opts.srcDir, "amazon")), amazon.WithSrcCompressFormat(opts.srcCompressFormat), amazon.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), amazon.WithDestDetectDir(filepath.Join(opts.destDir, "os", "amazon")), amazon.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build amazon")
			}
		case "arch":
			if err := arch.Build(arch.WithSrcDir(filepath.Join(opts.srcDir, "arch")), arch.WithSrcCompressFormat(opts.srcCompressFormat), arch.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), arch.WithDestDetectDir(filepath.Join(opts.destDir, "os", "arch")), arch.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build arch")
			}
		case "debian":
			if err := debian.Build(debian.WithSrcDir(filepath.Join(opts.srcDir, "debian")), debian.WithSrcCompressFormat(opts.srcCompressFormat), debian.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), debian.WithDestDetectDir(filepath.Join(opts.destDir, "os", "debian")), debian.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build debian")
			}
		case "debian-oval":
			if err := debianOval.Build(debianOval.WithSrcDir(filepath.Join(opts.srcDir, "debian", "oval")), debianOval.WithSrcCompressFormat(opts.srcCompressFormat), debianOval.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), debianOval.WithDestDetectDir(filepath.Join(opts.destDir, "os", "debian", "oval")), debianOval.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build debian oval")
			}
		case "debian-tracker":
			if err := debianTracker.Build(debianTracker.WithSrcDir(filepath.Join(opts.srcDir, "debian", "tracker")), debianTracker.WithSrcCompressFormat(opts.srcCompressFormat), debianTracker.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), debianTracker.WithDestDetectDir(filepath.Join(opts.destDir, "os", "debian", "tracker")), debianTracker.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build debian security tracker")
			}
		case "epel":
			// if err := epel.Build(epel.WithSrcDir(filepath.Join(opts.srcDir, "epel")), epel.WithSrcCompressFormat(opts.srcCompressFormat), epel.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), epel.WithDestDetectDir(filepath.Join(opts.destDir, "os", "epel")), epel.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build epel")
			// }
		case "fedora":
			// if err := fedora.Build(fedora.WithSrcDir(filepath.Join(opts.srcDir, "fedora")), fedora.WithSrcCompressFormat(opts.srcCompressFormat), fedora.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), fedora.WithDestDetectDir(filepath.Join(opts.destDir, "os", "fedora")), fedora.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build fedora")
			// }
		case "freebsd":
			if err := freebsd.Build(freebsd.WithSrcDir(filepath.Join(opts.srcDir, "freebsd")), freebsd.WithSrcCompressFormat(opts.srcCompressFormat), freebsd.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), freebsd.WithDestDetectDir(filepath.Join(opts.destDir, "os", "freebsd")), freebsd.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build freebsd")
			}
		case "gentoo":
			// if err := gentoo.Build(gentoo.WithSrcDir(filepath.Join(opts.srcDir, "gentoo")), gentoo.WithSrcCompressFormat(opts.srcCompressFormat), gentoo.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), gentoo.WithDestDetectDir(filepath.Join(opts.destDir, "os", "gentoo")), gentoo.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build gentoo")
			// }
		case "oracle":
			if err := oracle.Build(oracle.WithSrcDir(filepath.Join(opts.srcDir, "oracle")), oracle.WithSrcCompressFormat(opts.srcCompressFormat), oracle.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), oracle.WithDestDetectDir(filepath.Join(opts.destDir, "os", "oracle")), oracle.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build oracle")
			}
		case "redhat":
			if err := redhat.Build(redhat.WithSrcDir(filepath.Join(opts.srcDir, "redhat")), redhat.WithSrcCompressFormat(opts.srcCompressFormat), redhat.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), redhat.WithDestDetectDir(filepath.Join(opts.destDir, "os", "redhat")), redhat.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build redhat")
			}
		case "redhat-api":
			// if err := redhatAPI.Build(redhatAPI.WithSrcDir(filepath.Join(opts.srcDir, "redhat", "api")), redhatAPI.WithSrcCompressFormat(opts.srcCompressFormat), redhatAPI.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), redhatAPI.WithDestDetectDir(filepath.Join(opts.destDir, "os", "redhat", "api")), redhatAPI.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build redhat api")
			// }
		case "redhat-oval":
			if err := redhatOval.Build(redhatOval.WithSrcDir(filepath.Join(opts.srcDir, "redhat", "oval")), redhatOval.WithSrcCompressFormat(opts.srcCompressFormat), redhatOval.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), redhatOval.WithDestDetectDir(filepath.Join(opts.destDir, "os", "oval")), redhatOval.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build redhat oval")
			}
		case "rocky":
			// if err := rocky.Build(rocky.WithSrcDir(filepath.Join(opts.srcDir, "rocky")), rocky.WithSrcCompressFormat(opts.srcCompressFormat), rocky.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), rocky.WithDestDetectDir(filepath.Join(opts.destDir, "os", "rocky")), rocky.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build rocky")
			// }
		case "suse":
			if err := suse.Build(suse.WithSrcDir(filepath.Join(opts.srcDir, "suse")), suse.WithSrcCompressFormat(opts.srcCompressFormat), suse.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), suse.WithDestDetectDir(filepath.Join(opts.destDir, "os", "suse")), suse.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build suse")
			}
		case "suse-cvrf":
			if err := suseCvrf.Build(suseCvrf.WithSrcDir(filepath.Join(opts.srcDir, "suse", "cvrf")), suseCvrf.WithSrcCompressFormat(opts.srcCompressFormat), suseCvrf.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), suseCvrf.WithDestDetectDir(filepath.Join(opts.destDir, "os", "suse", "cvrf")), suseCvrf.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build suse cvrf")
			}
		case "suse-oval":
			if err := suseOval.Build(suseOval.WithSrcDir(filepath.Join(opts.srcDir, "suse", "oval")), suseOval.WithSrcCompressFormat(opts.srcCompressFormat), suseOval.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), suseOval.WithDestDetectDir(filepath.Join(opts.destDir, "os", "suse", "oval")), suseOval.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build suse oval")
			}
		case "ubuntu":
			if err := ubuntu.Build(ubuntu.WithSrcDir(filepath.Join(opts.srcDir, "ubuntu")), ubuntu.WithSrcCompressFormat(opts.srcCompressFormat), ubuntu.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), ubuntu.WithDestDetectDir(filepath.Join(opts.destDir, "os", "ubuntu")), ubuntu.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build ubuntu")
			}
		case "ubuntu-oval":
			if err := ubuntuOval.Build(ubuntuOval.WithSrcDir(filepath.Join(opts.srcDir, "ubuntu", "oval")), ubuntuOval.WithSrcCompressFormat(opts.srcCompressFormat), ubuntuOval.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), ubuntuOval.WithDestDetectDir(filepath.Join(opts.destDir, "os", "ubuntu", "oval")), ubuntuOval.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build ubuntu oval")
			}
		case "ubuntu-tracker":
			if err := ubuntuTracker.Build(ubuntuTracker.WithSrcDir(filepath.Join(opts.srcDir, "ubuntu", "tracker")), ubuntuTracker.WithSrcCompressFormat(opts.srcCompressFormat), ubuntuTracker.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), ubuntuTracker.WithDestDetectDir(filepath.Join(opts.destDir, "os", "ubuntu", "tracker")), ubuntuTracker.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
				return errors.Wrap(err, "failed to build ubuntu security tracker")
			}
		case "windows":
			// if err := windows.Build(windows.WithSrcDir(filepath.Join(opts.srcDir, "windows")), windows.WithSrcCompressFormat(opts.srcCompressFormat), windows.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), windows.WithDestDetectDir(filepath.Join(opts.destDir, "os", "windows")), windows.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build windows")
			// }

		// library
		case "cargo":
			// if err := cargo.Build(cargo.WithSrcDir(filepath.Join(opts.srcDir, "cargo")), cargo.WithSrcCompressFormat(opts.srcCompressFormat), cargo.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), cargo.WithDestDetectDir(filepath.Join(opts.destDir, "library", "cargo")), cargo.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build cargo")
			// }
		case "composer":
			// if err := composer.Build(composer.WithSrcDir(filepath.Join(opts.srcDir, "composer")), composer.WithSrcCompressFormat(opts.srcCompressFormat), composer.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), composer.WithDestDetectDir(filepath.Join(opts.destDir, "library", "composer")), composer.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build composer")
			// }
		case "conan":
			// if err := conan.Build(conan.WithSrcDir(filepath.Join(opts.srcDir, "conan")), conan.WithSrcCompressFormat(opts.srcCompressFormat), conan.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), conan.WithDestDetectDir(filepath.Join(opts.destDir, "library", "conan")), conan.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build conan")
			// }
		case "erlang":
			// if err := erlang.Build(erlang.WithSrcDir(filepath.Join(opts.srcDir, "erlang")), erlang.WithSrcCompressFormat(opts.srcCompressFormat), erlang.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), erlang.WithDestDetectDir(filepath.Join(opts.destDir, "library", "erlang")), erlang.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build erlang")
			// }
		case "golang":
			// if err := golang.Build(golang.WithSrcDir(filepath.Join(opts.srcDir, "golang")), golang.WithSrcCompressFormat(opts.srcCompressFormat), golang.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), golang.WithDestDetectDir(filepath.Join(opts.destDir, "library", "golang")), golang.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build golang")
			// }
		case "maven":
			// if err := maven.Build(maven.WithSrcDir(filepath.Join(opts.srcDir, "maven")), maven.WithSrcCompressFormat(opts.srcCompressFormat), maven.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), maven.WithDestDetectDir(filepath.Join(opts.destDir, "library", "maven")), maven.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build maven")
			// }
		case "npm":
			// if err := npm.Build(npm.WithSrcDir(filepath.Join(opts.srcDir, "npm")), npm.WithSrcCompressFormat(opts.srcCompressFormat), npm.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), npm.WithDestDetectDir(filepath.Join(opts.destDir, "library", "npm")), npm.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build npm")
			// }
		case "nuget":
			// if err := nuget.Build(nuget.WithSrcDir(filepath.Join(opts.srcDir, "nuget")), nuget.WithSrcCompressFormat(opts.srcCompressFormat), nuget.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), nuget.WithDestDetectDir(filepath.Join(opts.destDir, "library", "nuget")), nuget.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build nuget")
			// }
		case "pip":
			// if err := pip.Build(pip.WithSrcDir(filepath.Join(opts.srcDir, "pip")), pip.WithSrcCompressFormat(opts.srcCompressFormat), pip.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), pip.WithDestDetectDir(filepath.Join(opts.destDir, "library", "pip")), pip.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build pip")
			// }
		case "rubygems":
			// if err := rubygems.Build(rubygems.WithSrcDir(filepath.Join(opts.srcDir, "rubygems")), rubygems.WithSrcCompressFormat(opts.srcCompressFormat), rubygems.WithDestVulnDir(filepath.Join(opts.destDir, "vulnerability")), rubygems.WithDestDetectDir(filepath.Join(opts.destDir, "library", "rubygems")), rubygems.WithDestCompressFormat(opts.destCompressFormat)); err != nil {
			// 	return errors.Wrap(err, "failed to build rubygems")
			// }
		default:
			return fmt.Errorf("accepts %q, received %q", supports, name)
		}
	}
	return nil
}
