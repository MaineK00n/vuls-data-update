package dotgit

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/pull"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func newCmdPull() *cobra.Command {
	options := &struct {
		dir          string
		checkout     string
		restore      bool
		useNativeGit bool
	}{
		dir:          filepath.Join(util.CacheDir(), "dotgit"),
		checkout:     "main",
		restore:      false,
		useNativeGit: true,
	}

	cmd := &cobra.Command{
		Use:   "pull <repository>",
		Short: "Pull vuls-data-* dotgit from repository",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit pull ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := pull.Pull(args[0], pull.WithDir(options.dir), pull.WithCheckout(options.checkout), pull.WithRestore(options.restore), pull.WithUseNativeGit(options.useNativeGit)); err != nil {
				return errors.Wrap(err, "failed to dotgit pull")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "pull repository dotgit under the specified directory")
	cmd.Flags().StringVarP(&options.checkout, "checkout", "", options.checkout, "checkout to the specified branch or tag or commit")
	cmd.Flags().BoolVarP(&options.restore, "restore", "", options.restore, "do restore")
	cmd.Flags().BoolVarP(&options.useNativeGit, "use-native-git", "", options.useNativeGit, "use native git command instead of go-git")

	return cmd
}
