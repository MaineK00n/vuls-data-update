package dotgit

import (
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/remote/tag"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/remote/untag"
)

func newCmdRemote() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Operations for remote dotgits",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit remote tag ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-api:vuls-data-raw-debian-security-tracker-api vuls-data-raw-test
			$ vuls-data-update dotgit remote untag ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-api:vuls-data-raw-test
		`),
	}

	cmd.AddCommand(newCmdRemoteTag(), newCmdRemoteUntag())

	return cmd
}

func newCmdRemoteTag() *cobra.Command {
	options := &struct {
		token string
	}{
		token: os.Getenv("GITHUB_TOKEN"),
	}

	cmd := &cobra.Command{
		Use:   "tag <image> <new-tag>",
		Short: "Add new tag to remote dotgit images",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit remote tag ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-api vuls-data-raw-test
			$ vuls-data-update dotgit remote tag ghcr.io/vulsio/vuls-data-db@sha256:5b71484ba9f1565f7ed5cd3aa34b027c44e1773a6e418328ea38a05f9b459f23 vuls-raw-test
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := tag.Tag(args[0], args[1], options.token); err != nil {
				return errors.Wrap(err, "failed to add tag")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.token, "token", "", options.token, "specify GitHub token")

	return cmd
}

func newCmdRemoteUntag() *cobra.Command {
	options := &struct {
		token string
	}{
		token: os.Getenv("GITHUB_TOKEN"),
	}

	cmd := &cobra.Command{
		Use:   "untag <image>",
		Short: "Remove tag from remote dotgit images",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit remote untag ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := untag.Untag(args[0], options.token); err != nil {
				return errors.Wrap(err, "failed to remove tag")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.token, "token", "", options.token, "specify GitHub token")

	return cmd
}
