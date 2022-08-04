package fetch

import (
	"fmt"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/alma"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/alpine"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/amazon"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/arch"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/debian"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/oracle"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu"
)

var (
	supportOS      = []string{"alma", "alpine", "amazon", "arch", "debian", "epel", "fedora", "gentoo", "oracle", "redhat", "rocky", "suse", "ubuntu", "windows"}
	supportLibrary = []string{"cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems"}
	supportOther   = []string{"cti", "cwe", "exploit", "jvn", "kev", "mitre", "msfdb", "nvd"}
)

func NewCmdFetch() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch <subcommand> <data source>",
		Short: "Fetch data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch os debian
			$ vuls-data-update fetch library cargo
			$ vuls-data-update fetch other nvd
		`),
	}

	cmd.AddCommand(newCmdFetchOS())
	cmd.AddCommand(newCmdFetchLibrary())
	cmd.AddCommand(newCmdFetchOther())

	return cmd
}

func newCmdFetchOS() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "os <os name>",
		Short:     "Fetch OS data source",
		Args:      cobra.ExactValidArgs(1),
		ValidArgs: supportOS,
		RunE: func(_ *cobra.Command, args []string) error {
			return fetchOSRun(args[0])
		},
		Example: heredoc.Doc(`
			$ vuls-data-update fetch os debian
		`),
	}
	return cmd
}

func fetchOSRun(name string) error {
	switch name {
	case "alma":
		if err := alma.Fetch(); err != nil {
			return errors.Wrap(err, "failed to fetch almalinux")
		}
	case "alpine":
		if err := alpine.Fetch(); err != nil {
			return errors.Wrap(err, "failed to fetch alpine linux")
		}
	case "amazon":
		if err := amazon.Fetch(); err != nil {
			return errors.Wrap(err, "failed to fetch amazon linux")
		}
	case "arch":
		if err := arch.Fetch(); err != nil {
			return errors.Wrap(err, "failed to fetch arch linux")
		}
	case "debian":
		if err := debian.Fetch(); err != nil {
			return errors.Wrap(err, "failed to fetch debian")
		}
	case "epel":
	case "fedora":
	case "gentoo":
	case "oracle":
		if err := oracle.Fetch(); err != nil {
			return errors.Wrap(err, "failed to fetch oracle linux")
		}
	case "redhat":
	case "rocky":
	case "suse":
	case "ubuntu":
		if err := ubuntu.Fetch(); err != nil {
			return errors.Wrap(err, "failed to fetch ubuntu")
		}
	case "windows":
	default:
		return fmt.Errorf("accepts %q, received %q", supportOS, name)
	}
	return nil
}

func newCmdFetchLibrary() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "library <library name>",
		Short:     "Fetch Library data source",
		Args:      cobra.ExactValidArgs(1),
		ValidArgs: supportLibrary,
		RunE: func(_ *cobra.Command, args []string) error {
			return fetchLibraryRun(args[0])
		},
		Example: heredoc.Doc(`
			$ vuls-data-update fetch library cargo
		`),
	}
	return cmd
}

func fetchLibraryRun(name string) error {
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
	return nil
}

func newCmdFetchOther() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "other <data name>",
		Short:     "Fetch Other data source",
		Args:      cobra.ExactValidArgs(1),
		ValidArgs: supportOther,
		RunE: func(_ *cobra.Command, args []string) error {
			return fetchOtherRun(args[0])
		},
		Example: heredoc.Doc(`
			$ vuls-data-update fetch other nvd
		`),
	}
	return cmd
}

func fetchOtherRun(name string) error {
	switch name {
	case "cti":
	case "cwe":
	case "exploit":
	case "jvn":
	case "kev":
	case "mitre":
	case "msfdb":
	case "nvd":
	default:
		return fmt.Errorf("accepts %q, received %q", supportOther, name)
	}
	return nil
}
