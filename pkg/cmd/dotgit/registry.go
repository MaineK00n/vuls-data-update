package dotgit

import (
	"encoding/json"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/ls"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/status"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/tag"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/registry/untag"
)

func newCmdRegistry() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Operations for registry dotgits",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit registry ls
			$ vuls-data-update dotgit registry status ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-api
			$ vuls-data-update dotgit registry tag ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-api vuls-data-raw-test
			$ vuls-data-update dotgit registry untag ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test
		`),
	}

	cmd.AddCommand(
		newCmdRegistryLs(), newCmdRegistryStatus(),
		newCmdRegistryTag(), newCmdRegistryUntag(),
	)

	return cmd
}

func newCmdRegistryLs() *cobra.Command {
	options := &struct {
		registries []string
		token      string
	}{
		registries: []string{"org:vulsio/vuls-data-db", "org:vulsio/vuls-data-db-archive", "org:vulsio/vuls-data-db-backup"},
		token:      os.Getenv("GITHUB_TOKEN"),
	}

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List registry dotgit images",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit registry ls
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ps, err := ls.List(options.registries, options.token)
			if err != nil {
				return errors.Wrap(err, "failed to list registry dotgits")
			}
			e := json.NewEncoder(os.Stdout)
			e.SetIndent("", "  ")
			if err := e.Encode(ps); err != nil {
				return errors.Wrap(err, "failed to print registry dotgits")
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&options.registries, "registries", "", options.registries, "specify registries. format: <type: (org|user)>:<name>/<package name>")
	cmd.Flags().StringVarP(&options.token, "token", "", options.token, "specify GitHub token")

	return cmd
}

func newCmdRegistryStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <image>",
		Short: "Show registry dotgit image status",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit registry status ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-api
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := status.Status(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to get registry dotgit status")
			}
			if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
				return errors.Wrap(err, "failed to print registry dotgit status")
			}
			return nil
		},
	}

	return cmd
}

func newCmdRegistryTag() *cobra.Command {
	options := &struct {
		token string
	}{
		token: os.Getenv("GITHUB_TOKEN"),
	}

	cmd := &cobra.Command{
		Use:   "tag <image> <new-tag>",
		Short: "Add new tag to registry dotgit images",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit registry tag ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-api vuls-data-raw-test
			$ vuls-data-update dotgit registry tag ghcr.io/vulsio/vuls-data-db@sha256:5b71484ba9f1565f7ed5cd3aa34b027c44e1773a6e418328ea38a05f9b459f23 vuls-raw-test
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

func newCmdRegistryUntag() *cobra.Command {
	options := &struct {
		token string
	}{
		token: os.Getenv("GITHUB_TOKEN"),
	}

	cmd := &cobra.Command{
		Use:   "untag <image>",
		Short: "Remove tag from registry dotgit images",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit registry untag ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test
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
