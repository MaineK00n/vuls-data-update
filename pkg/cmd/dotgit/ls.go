package dotgit

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/ls"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func newCmdLs() *cobra.Command {
	options := &struct {
		dir string
	}{
		dir: filepath.Join(util.CacheDir(), "dotgit"),
	}

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List local dotgit images",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit ls
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ds, err := ls.List(ls.WithDir(options.dir))
			if err != nil {
				return errors.Wrap(err, "failed to list local dotgits")
			}
			for _, d := range ds {
				if _, err := fmt.Fprintln(os.Stdout, d); err != nil {
					return errors.Wrap(err, "failed to print local dotgit")
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "specify vuls-data-update dotgit directory")

	return cmd
}
