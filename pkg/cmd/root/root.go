package root

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	dotgitCmd "github.com/MaineK00n/vuls-data-update/pkg/cmd/dotgit"
	extractCmd "github.com/MaineK00n/vuls-data-update/pkg/cmd/extract"
	fetchCmd "github.com/MaineK00n/vuls-data-update/pkg/cmd/fetch"
)

func NewCmdRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "vuls-data-update <command>",
		Short:         "Vuls data update",
		Long:          "Fetch and Extract data source, Operate vuls-data-* dotgit",
		SilenceErrors: true,
		SilenceUsage:  true,
		Example: heredoc.Doc(`
			$ vuls-data-update fetch debian-security-tracker-salsa
			$ vuls-data-update extract debian-security-tracker-salsa vuls-data-raw-debian-security-tracker-salsa
			$ vuls-data-update dotgit pull ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-salsa
		`),
	}

	cmd.AddCommand(fetchCmd.NewCmdFetch(), extractCmd.NewCmdExtract(), dotgitCmd.NewCmdDotGit())

	return cmd
}
