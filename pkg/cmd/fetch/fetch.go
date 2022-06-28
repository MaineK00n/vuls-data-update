package fetch

import (
	"fmt"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
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
	case "alpine":
	case "amazon":
	case "arch":
	case "debian":
	case "epel":
	case "fedora":
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
		return fmt.Errorf("accepts %q, received %q", supportOS, name)
	}
	return nil
}
