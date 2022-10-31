package build

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/build/other/epss"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/mitre"
	"github.com/MaineK00n/vuls-data-update/pkg/build/other/nvd"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
)

var (
	supportOS      = []string{"alma", "alpine", "amazon", "arch", "debian", "epel", "fedora", "freebsd", "gentoo", "oracle", "redhat", "rocky", "suse", "ubuntu", "windows"}
	supportLibrary = []string{"cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems"}
	supportOther   = []string{"mitre", "nvd", "jvn", "epss", "msf", "exploit", "kev", "cwe", "cti"}
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

	for _, name := range supportOther {
		switch name {
		case "cti":
		case "cwe":
			// if err := cwe.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build cwe")
			// }
		case "epss":
			if err := epss.Build(); err != nil {
				return errors.Wrap(err, "failed to build epss")
			}
		case "exploit":
			// if err := exploit.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build exploit")
			// }
		case "jvn":
			// if err := jvn.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build jvn")
			// }
		case "kev":
			// if err := kev.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build kev")
			// }
		case "mitre":
			if err := mitre.Build(); err != nil {
				return errors.Wrap(err, "failed to build mitre")
			}
		case "msf":
			// if err := msf.Build(); err != nil {
			// 	return errors.Wrap(err, "failed to build msf")
			// }
		case "nvd":
			if err := nvd.Build(); err != nil {
				return errors.Wrap(err, "failed to build nvd")
			}
		default:
			return fmt.Errorf("accepts %q, received %q", supportOther, name)
		}
	}

	for _, name := range supportOS {
		switch name {
		case "alma":
		case "alpine":
		case "amazon":
		case "arch":
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
		default:
			return fmt.Errorf("accepts %q, received %q", supportOS, name)
		}
	}

	for _, name := range supportLibrary {
		switch name {
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
			return fmt.Errorf("accepts %q, received %q", supportLibrary, name)
		}
	}

	return nil
}
