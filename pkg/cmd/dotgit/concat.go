package dotgit

import (
	"encoding/json/v2"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/concat"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func newCmdConcat() *cobra.Command {
	options := &struct {
		dir     string
		maxSize int64
		dryRun  bool
	}{
		dir:     filepath.Join(util.CacheDir(), "dotgit", "concat"),
		maxSize: 0,
		dryRun:  false,
	}

	cmd := &cobra.Command{
		Use:   "concat <repository path>...",
		Short: "Join vuls-data-* dotgit archives, oldest first, each continuing from the one before it",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit concat --dir joined vuls-data-raw-suse-oval-archive-70 vuls-data-raw-suse-oval-archive-71 vuls-data-raw-suse-oval-archive-72
			$ vuls-data-update dotgit concat --dir joined --max-size 9000000000 --dry-run vuls-data-raw-suse-oval-archive-1 vuls-data-raw-suse-oval-archive-2 vuls-data-raw-suse-oval-archive-3
			$ vuls-data-update dotgit concat --dir joined vuls-data-raw-suse-oval-archive-72 vuls-data-raw-suse-oval
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			outputs, err := concat.Concat(args, concat.WithDir(options.dir), concat.WithMaxSize(options.maxSize), concat.WithDryRun(options.dryRun))
			if err != nil {
				return errors.Wrap(err, "failed to dotgit concat")
			}
			if err := json.MarshalWrite(os.Stdout, outputs, json.Deterministic(true)); err != nil {
				return errors.Wrap(err, "failed to print dotgit concat outputs")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "create the joined repositories under the specified directory, each named after its last input")
	cmd.Flags().Int64VarP(&options.maxSize, "max-size", "", options.maxSize, "split the inputs, oldest first, into groups whose pack is predicted to stay within this many bytes (0: one group); the .git directory also holds the pack index and the index of HEAD's files")
	cmd.Flags().BoolVarP(&options.dryRun, "dry-run", "", options.dryRun, "show the groups without joining them")

	return cmd
}
