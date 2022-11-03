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
		case "capec":
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
		case "epel":
		case "fedora":
		case "freebsd":
		case "gentoo":
		case "oracle":
		case "redhat":
		case "rocky":
		case "suse":
		case "ubuntu":
		case "windows":

		// library
		case "cargo":
		case "composer":
		case "conan":
		case "erlang":
		case "golang":
		case "maven":
		case "npm":
		case "nuget":
		case "pip":
		case "rubygems":
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
