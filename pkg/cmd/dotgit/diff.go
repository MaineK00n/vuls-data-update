package dotgit

import (
	"fmt"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/diff"
)

func newCmdDiff() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <repository> <MINUS_FILE:<treeish:path>> <PLUS_FILE:<treeish:path>>",
		Short: "Diff files in the specified treeish",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit diff vuls-data-raw-debian-security-tracker 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3:bookworm/2025/CVE-2025-0001.json main:bookworm/2025/CVE-2025-0001.json
		`),
		Args: cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			content, err := diff.Diff(args[0], args[1], args[2])
			if err != nil {
				return errors.Wrap(err, "failed to dotgit diff")
			}

			if content != "" {
				if _, err := fmt.Fprintln(os.Stdout, content); err != nil {
					return errors.Wrap(err, "failed to print diff")
				}
			}

			return nil
		},
	}

	return cmd
}
