package dotgit

import (
	"fmt"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/compress"
)

func newCmdCompress() *cobra.Command {
	options := &struct {
		output string
		root   string

		level int
	}{
		output: "",
		root:   "",

		level: 3,
	}

	cmd := &cobra.Command{
		Use:   "compress <repository path>",
		Short: "Compress vuls-data-* dotgit with Zstandard",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit compress vuls-data-raw-debian-security-tracker
			$ vuls-data-update dotgit compress vuls-data-raw-debian-security-tracker-archive-1 --output /tmp/vuls-data-raw-debian-security-tracker.tar.zst --root vuls-data-raw-debian-security-tracker 
		`),
		Args: cobra.ExactArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			abs, err := filepath.Abs(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to get absolute path")
			}

			if options.output == "" {
				options.output = fmt.Sprintf("%s.tar.zst", filepath.Base(abs))
			}

			if options.root == "" {
				options.root = filepath.Base(abs)
			}

			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if err := compress.Compress(args[0], options.output, compress.WithRoot(options.root), compress.WithLevel(options.level)); err != nil {
				return errors.Wrap(err, "failed to dotgit compress")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.output, "output", "o", options.output, "output to a specified file")
	cmd.Flags().StringVarP(&options.root, "root", "", options.root, "root directory name when compressing")
	cmd.Flags().IntVarP(&options.level, "level", "L", options.level, "compression level (1-22)")

	return cmd
}
