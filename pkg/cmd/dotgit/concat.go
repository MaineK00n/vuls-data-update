package dotgit

import (
	"encoding/json/v2"
	"math"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/concat"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func newCmdConcat() *cobra.Command {
	options := &struct {
		dir     string
		maxSize byteSize
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
			$ vuls-data-update dotgit concat --dir joined --max-size 9GB --dry-run vuls-data-raw-suse-oval-archive-1 vuls-data-raw-suse-oval-archive-2 vuls-data-raw-suse-oval-archive-3
			$ vuls-data-update dotgit concat --dir joined vuls-data-raw-suse-oval-archive-72 vuls-data-raw-suse-oval
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			outputs, err := concat.Concat(args, concat.WithDir(options.dir), concat.WithMaxSize(int64(options.maxSize)), concat.WithDryRun(options.dryRun))
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
	cmd.Flags().VarP(&options.maxSize, "max-size", "", "split the inputs, oldest first, into groups whose pack is predicted to stay within this size, and fail if a .git directory comes out larger (0: one group); leave room for the pack index and the index of HEAD's files. Takes bytes or a unit: GB and G are 10^9 bytes, GiB is 2^30, unlike git's g (e.g. 9GB, 9GiB, 9000000000)")
	cmd.Flags().BoolVarP(&options.dryRun, "dry-run", "", options.dryRun, "show the groups without joining them")

	return cmd
}

// byteSize is a size in bytes that a flag takes as bytes or with a unit, as
// humanize.ParseBytes reads it.
type byteSize int64

func (b *byteSize) String() string {
	if *b == 0 {
		// pflag leaves out a default of "0", which means no limit here.
		return "0"
	}
	return humanize.Bytes(uint64(*b))
}

func (b *byteSize) Set(v string) error {
	n, err := humanize.ParseBytes(v)
	if err != nil {
		return errors.Wrapf(err, "parse %q", v)
	}
	if n > math.MaxInt64 {
		return errors.Errorf("unexpected size. expected: <= %d, actual: %q", int64(math.MaxInt64), v)
	}
	*b = byteSize(n)
	return nil
}

func (b *byteSize) Type() string {
	return "size"
}
