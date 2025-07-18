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
			$ vuls-data-update dotgit compress vuls-data-raw-debian-security-tracker-api

			$ vuls-data-update dotgit contains ~/.cache/vuls-data-update/dotgit/vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3
			$ vuls-data-update dotgit find --treeish HEAD vuls-data-raw-debian-security-tracker-api CVE-2025-0001.json
			$ vuls-data-update dotgit grep vuls-data-raw-debian-security-tracker-api CVE-2025-0001

			$ vuls-data-update dotgit cat --treeish HEAD vuls-data-raw-debian-security-tracker-api bookworm/2025/CVE-2025-0001.json
			$ vuls-data-update dotgit diff file vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3:bookworm/2025/CVE-2025-0001.json main:bookworm/2025/CVE-2025-0001.json
			$ vuls-data-update dotgit diff tree --pathspec bookworm/2025/CVE-2025-0001.json vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3 main

			$ vuls-data-update dotgit log vuls-data-raw-debian-security-tracker-api
			
			$ vuls-data-update dotgit ls local
			$ vuls-data-update dotgit ls remote
			$ vuls-data-update dotgit status local vuls-data-raw-debian-security-tracker-api
			$ vuls-data-update dotgit status remote ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-api
		`),
	}

	cmd.AddCommand(
		newCmdPull(), newCmdCompress(),
		newCmdContains(), newCmdFind(), newCmdGrep(),
		newCmdCat(), newCmdDiff(),
		newCmdLog(),
		newCmdLs(),
		newCmdStatus(),
	)

	return cmd
}
