package dotgit

import (
	"fmt"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/diff/file"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/diff/tree"
)

func newCmdDiff() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff file, tree in the specified treeish",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit diff file vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3:bookworm/2025/CVE-2025-0001.json main:bookworm/2025/CVE-2025-0001.json
			$ vuls-data-update dotgit diff tree vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3 main
			$ vuls-data-update dotgit diff tree --pathspec bookworm/2025/CVE-2025-0001.json vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3 main
		`),
	}

	cmd.AddCommand(newCmdDiffFile(), newCmdDiffTree())

	return cmd
}

func newCmdDiffFile() *cobra.Command {
	options := &struct {
		useNativeGit bool
		color        bool
	}{
		useNativeGit: true,
		color:        false,
	}

	cmd := &cobra.Command{
		Use:   "file <repository> <MINUS_FILE:<treeish:path>> <PLUS_FILE:<treeish:path>>",
		Short: "Diff file in the specified treeish",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit diff file vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3:bookworm/2025/CVE-2025-0001.json main:bookworm/2025/CVE-2025-0001.json
		`),
		Args: cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			content, err := file.Diff(args[0], args[1], args[2], file.WithUseNativeGit(options.useNativeGit), file.WithColor(options.color))
			if err != nil {
				return errors.Wrap(err, "failed to dotgit diff file")
			}

			if content != "" {
				if _, err := fmt.Fprintln(os.Stdout, content); err != nil {
					return errors.Wrap(err, "failed to print diff file")
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&options.useNativeGit, "use-native-git", "", options.useNativeGit, "use native git command instead of go-git")
	cmd.Flags().BoolVarP(&options.color, "color", "", options.color, "color the diff")

	return cmd
}

func newCmdDiffTree() *cobra.Command {
	options := &struct {
		useNativeGit bool
		color        bool
		pathspecs    []string
	}{
		useNativeGit: true,
		color:        false,
		pathspecs:    nil,
	}

	cmd := &cobra.Command{
		Use:   "tree <repository> <minus treeish> <plus treeish>",
		Short: "Diff tree in the specified treeish",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit diff tree vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3 main
			$ vuls-data-update dotgit diff tree --pathspec bookworm/2025/CVE-2025-0001.json vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3 main
		`),
		Args: cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			content, err := tree.Diff(args[0], args[1], args[2], tree.WithUseNativeGit(options.useNativeGit), tree.WithColor(options.color), tree.WithPathSpecs(options.pathspecs))
			if err != nil {
				return errors.Wrap(err, "failed to dotgit diff tree")
			}

			if content != "" {
				if _, err := fmt.Fprintln(os.Stdout, content); err != nil {
					return errors.Wrap(err, "failed to print diff tree")
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&options.useNativeGit, "use-native-git", "", options.useNativeGit, "use native git command instead of go-git")
	cmd.Flags().BoolVarP(&options.color, "color", "", options.color, "color the diff")
	cmd.Flags().StringArrayVarP(&options.pathspecs, "pathspec", "p", options.pathspecs, "grep in specified pathspec")

	return cmd
}
