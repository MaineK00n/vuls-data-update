package root

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	extractCmd "github.com/MaineK00n/vuls-data-update/pkg/cmd/extract"
	fetchCmd "github.com/MaineK00n/vuls-data-update/pkg/cmd/fetch"
)

func NewCmdRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "vuls-data-update <command> <subcommand> ([os|library|other])",
		Short:         "Vuls data update",
		Long:          "Fetch and Extract data source",
		SilenceErrors: true,
		SilenceUsage:  true,
		Example: heredoc.Doc(`
			$ vuls-data-update fetch debian-security-tracker
			$ vuls-data-update fetch cargo-db
			$ vuls-data-update fetch nvd-feed
		`),
	}

	cmd.AddCommand(fetchCmd.NewCmdFetch(), extractCmd.NewCmdExtract())

	return cmd
}
