package dotgit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/ls/local"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/ls/remote"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func newCmdLs() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List dotgits",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit ls local
			$ vuls-data-update dotgit ls remote
		`),
	}

	cmd.AddCommand(newCmdLsLocal(), newCmdLsRemote())

	return cmd
}

func newCmdLsLocal() *cobra.Command {
	options := &struct {
		dir string
	}{
		dir: filepath.Join(util.CacheDir(), "dotgit"),
	}

	cmd := &cobra.Command{
		Use:   "local",
		Short: "List local dotgits",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit ls local
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ds, err := local.List(local.WithDir(options.dir))
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

func newCmdLsRemote() *cobra.Command {
	options := &struct {
		remotes []string
		token   string
	}{
		remotes: []string{"org:vulsio/vuls-data-db", "org:vulsio/vuls-data-db-archive", "org:vulsio/vuls-data-db-backup"},
		token:   os.Getenv("GITHUB_TOKEN"),
	}

	cmd := &cobra.Command{
		Use:   "remote",
		Short: "List remote dotgits",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit ls remote
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ps, err := remote.List(options.remotes, options.token)
			if err != nil {
				return errors.Wrap(err, "failed to list remote dotgits")
			}
			e := json.NewEncoder(os.Stdout)
			e.SetIndent("", "  ")
			if err := e.Encode(ps); err != nil {
				return errors.Wrap(err, "failed to print remote dotgits")
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&options.remotes, "remotes", "", options.remotes, "specify remote repositories. format: <type: (org|user)>:<name>/<package name>")
	cmd.Flags().StringVarP(&options.token, "token", "", options.token, "specify GitHub token")

	return cmd
}
