package dotgit

import (
	"fmt"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/cat"
)

func newCmdCat() *cobra.Command {
	options := &struct {
		treeish string
	}{
		treeish: "main",
	}

	cmd := &cobra.Command{
		Use:   "cat <repository> <path>",
		Short: "Print the file content of the specified path, in the specified treeish",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit cat --treeish HEAD vuls-data-raw-debian-security-tracker bookworm/2025/CVE-2025-0001.json
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			content, err := cat.Cat(args[0], args[1], cat.WithTreeish(options.treeish))
			if err != nil {
				return errors.Wrap(err, "failed to dotgit cat")
			}

			if _, err := fmt.Fprintln(os.Stdout, content); err != nil {
				return errors.Wrap(err, "failed to print file")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&options.treeish, "treeish", "", options.treeish, "cat file in specified treeish")

	return cmd
}
