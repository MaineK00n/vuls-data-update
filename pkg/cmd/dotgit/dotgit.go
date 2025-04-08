package dotgit

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

func NewCmdDotGit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dotgit <subcommand>",
		Short: "Operate vuls-data-* dotgit",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit pull ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-salsa
		`),
	}

	cmd.AddCommand(
		newCmdPull(), newCmdCompress(),
		newCmdContains(), newCmdDiff(),
	)

	return cmd
}
