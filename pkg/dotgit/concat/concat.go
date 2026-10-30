package concat

import (
	"bytes"
	stderrors "errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	dir     string
	maxSize int64
	dryRun  bool
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type maxSizeOption int64

func (m maxSizeOption) apply(opts *options) {
	opts.maxSize = int64(m)
}

// WithMaxSize splits the inputs, oldest first, into groups whose pack is
// predicted to stay within size bytes, and fails if a pack comes out larger.
// The .git directory, and so its tarball, holds more than the pack: the pack
// index, and the index of HEAD's files, which for 2.9 million files took 446
// MiB before compression. 0 keeps the inputs in one group.
func WithMaxSize(size int64) Option {
	return maxSizeOption(size)
}

type dryRunOption bool

func (d dryRunOption) apply(opts *options) {
	opts.dryRun = bool(d)
}

func WithDryRun(dryRun bool) Option {
	return dryRunOption(dryRun)
}

// Output is a group of inputs and the repository that joins them, named after
// the last of them. A group of one input has nothing to join, so no
// repository and no Path.
type Output struct {
	Name    string   `json:"name"`
	Path    string   `json:"path,omitempty"`
	Inputs  []string `json:"inputs"`
	Commits int      `json:"commits"`
	Shallow []string `json:"shallow,omitempty"`
	Size    Size     `json:"size"`
}

type Size struct {
	// Predicted is the on-disk size of the group's objects as the inputs store
	// them. The repack finds deltas between the inputs, so the pack comes out
	// smaller.
	Predicted int64 `json:"predicted"`
	// Pack is the size of the pack made.
	Pack int64 `json:"pack,omitempty"`
	// DotGit is the size of the .git directory made.
	DotGit int64 `json:"dotgit,omitempty"`
}

type input struct {
	path    string
	head    string
	refs    map[string]string
	origin  string
	shallow []string
	commits []string
	// all is the on-disk size of every object its branches and tags reach.
	all int64
	// added is the part of all its own commits add to its shallow roots,
	// which is what it adds to a group continuing from the input before it.
	added int64
}

type group []input

// Concat joins repositories, oldest first, where each one continues from an
// earlier one: its shallow roots are commits an earlier one has, as a dotgit
// archive starts from the last commit of the archive before it. Each joined
// repository keeps the branches of its last input, the tags of every input, a
// tag "<input name>/<branch>" at every input's branch tips, and the origin URL
// of its last input. The inputs are left as they are.
func Concat(repositories []string, opts ...Option) ([]Output, error) {
	options := &options{
		dir:     filepath.Join(util.CacheDir(), "dotgit", "concat"),
		maxSize: 0,
		dryRun:  false,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if len(repositories) == 0 {
		return nil, errors.New("no repository to concat")
	}

	inputs := make([]input, 0, len(repositories))
	for _, r := range repositories {
		in, err := inspect(r)
		if err != nil {
			return nil, errors.Wrapf(err, "inspect %s", r)
		}
		inputs = append(inputs, in)
	}

	if err := checkChain(inputs); err != nil {
		return nil, errors.Wrap(err, "check chain")
	}

	groups := split(inputs, options.maxSize)

	outputs := make([]Output, 0, len(groups))
	for _, g := range groups {
		o, err := g.output(options.dir)
		if err != nil {
			return nil, errors.Wrapf(err, "plan %s", filepath.Base(g[len(g)-1].path))
		}

		if o.Path != "" {
			switch _, err := os.Stat(o.Path); {
			case err == nil:
				return nil, errors.Errorf("%s already exists", o.Path)
			case errors.Is(err, fs.ErrNotExist):
			default:
				return nil, errors.Wrapf(err, "stat %s", o.Path)
			}
		}

		outputs = append(outputs, o)
	}

	if options.dryRun {
		return outputs, nil
	}

	for i, g := range groups {
		if outputs[i].Path == "" {
			continue
		}

		slog.Info("Concat dotgit", slog.String("dst", outputs[i].Path), slog.Int("inputs", len(g)), slog.Int64("predicted", outputs[i].Size.Predicted))

		pack, dotgit, err := func() (int64, int64, error) {
			pack, dotgit, err := g.build(outputs[i])
			if err != nil {
				return 0, 0, errors.Wrap(err, "build")
			}
			if options.maxSize > 0 && pack > options.maxSize {
				return 0, 0, errors.Errorf("unexpected pack size. expected: <= %d, actual: %d", options.maxSize, pack)
			}
			return pack, dotgit, nil
		}()
		if err != nil {
			if err2 := os.RemoveAll(outputs[i].Path); err2 != nil {
				err = stderrors.Join(err, errors.Wrapf(err2, "remove %s", outputs[i].Path))
			}
			return nil, errors.Wrapf(err, "concat to %s", outputs[i].Path)
		}
		outputs[i].Size.Pack = pack
		outputs[i].Size.DotGit = dotgit
	}

	return outputs, nil
}

func inspect(repository string) (input, error) {
	path, err := filepath.Abs(repository)
	if err != nil {
		return input{}, errors.Wrapf(err, "absolute path of %s", repository)
	}

	bs, err := git("-C", path, "symbolic-ref", "HEAD")
	if err != nil {
		return input{}, errors.Wrap(err, "read HEAD")
	}
	head := strings.TrimSpace(string(bs))

	bs, err = git("-C", path, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads/", "refs/tags/")
	if err != nil {
		return input{}, errors.Wrap(err, "list branches and tags")
	}
	refs := make(map[string]string)
	for line := range strings.Lines(string(bs)) {
		name, oid, ok := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
		if !ok {
			return input{}, errors.Errorf("unexpected ref line. expected: %q, actual: %q", "<ref> <object>", line)
		}
		refs[name] = oid
	}
	if _, ok := refs[head]; !ok {
		return input{}, errors.Errorf("HEAD points to %s, which has no commit", head)
	}

	bs, err = git("-C", path, "config", "--default", "", "--get", "remote.origin.url")
	if err != nil {
		return input{}, errors.Wrap(err, "get origin url")
	}
	origin := strings.TrimSpace(string(bs))

	bs, err = git("-C", path, "rev-parse", "--path-format=absolute", "--git-path", "shallow")
	if err != nil {
		return input{}, errors.Wrap(err, "locate shallow file")
	}
	var shallow []string
	switch content, err := os.ReadFile(strings.TrimSpace(string(bs))); {
	case err == nil:
		shallow = strings.Fields(string(content))
		slices.Sort(shallow)
	case errors.Is(err, fs.ErrNotExist):
	default:
		return input{}, errors.Wrapf(err, "read %s", strings.TrimSpace(string(bs)))
	}

	bs, err = git("-C", path, "rev-list", "--branches", "--tags")
	if err != nil {
		return input{}, errors.Wrap(err, "list commits")
	}
	commits := strings.Fields(string(bs))
	slices.Sort(commits)

	all, err := diskUsage(path, "--branches", "--tags")
	if err != nil {
		return input{}, errors.Wrap(err, "disk usage of all objects")
	}

	added := all
	if len(shallow) > 0 {
		added, err = diskUsage(path, append([]string{"--branches", "--tags", "--not"}, shallow...)...)
		if err != nil {
			return input{}, errors.Wrap(err, "disk usage of objects beyond the shallow roots")
		}
	}

	return input{
		path:    path,
		head:    head,
		refs:    refs,
		origin:  origin,
		shallow: shallow,
		commits: commits,
		all:     all,
		added:   added,
	}, nil
}

// checkChain refuses inputs that would leave a gap: a shallow root of an input
// that no input before it has. An input before it may have that commit as a
// shallow root too, as an archive made from a repository of one commit does.
func checkChain(inputs []input) error {
	seen := make(map[string]struct{})
	for i, in := range inputs {
		if i > 0 {
			for _, s := range in.shallow {
				if _, ok := seen[s]; !ok {
					return errors.Errorf("%s does not continue from the inputs before it: none of them has its shallow root %s", in.path, s)
				}
			}
		}
		for _, c := range in.commits {
			seen[c] = struct{}{}
		}
	}
	return nil
}

// complete is the commits the input holds with their parents.
func (in input) complete() []string {
	return slices.DeleteFunc(slices.Clone(in.commits), func(c string) bool {
		_, found := slices.BinarySearch(in.shallow, c)
		return found
	})
}

func split(inputs []input, maxSize int64) []group {
	var (
		groups []group
		size   int64
	)
	for i, in := range inputs {
		if i > 0 && (maxSize <= 0 || size+in.added <= maxSize) {
			groups[len(groups)-1] = append(groups[len(groups)-1], in)
			size += in.added
			continue
		}
		groups = append(groups, group{in})
		size = in.all
	}
	return groups
}

func (g group) output(dir string) (Output, error) {
	last := g[len(g)-1]

	o := Output{
		Name:    filepath.Base(last.path),
		Inputs:  make([]string, 0, len(g)),
		Commits: len(g.commits()),
		Shallow: g.shallow(),
		Size: Size{
			Predicted: g[0].all,
		},
	}
	for i, in := range g {
		o.Inputs = append(o.Inputs, in.path)
		if i > 0 {
			o.Size.Predicted += in.added
		}
	}

	if len(g) > 1 {
		path, err := filepath.Abs(filepath.Join(dir, o.Name))
		if err != nil {
			return Output{}, errors.Wrapf(err, "absolute path of %s", filepath.Join(dir, o.Name))
		}
		o.Path = path
	}

	return o, nil
}

func (g group) commits() []string {
	var cs []string
	for _, in := range g {
		cs = append(cs, in.commits...)
	}
	slices.Sort(cs)
	return slices.Compact(cs)
}

// shallow is the shallow roots no input of the group holds the history of.
// Every input's shallow roots taken together would cut the history at the
// point where each input continues from the one before it.
func (g group) shallow() []string {
	held := make(map[string]struct{})
	for _, in := range g {
		for _, c := range in.complete() {
			held[c] = struct{}{}
		}
	}

	var shallow []string
	for _, in := range g {
		for _, s := range in.shallow {
			if _, ok := held[s]; !ok {
				shallow = append(shallow, s)
			}
		}
	}
	slices.Sort(shallow)
	return slices.Compact(shallow)
}

func (g group) build(o Output) (int64, int64, error) {
	last := g[len(g)-1]

	if _, err := git("init", "--quiet", o.Path); err != nil {
		return 0, 0, errors.Wrap(err, "init")
	}
	if _, err := git("-C", o.Path, "symbolic-ref", "HEAD", last.head); err != nil {
		return 0, 0, errors.Wrapf(err, "point HEAD to %s", last.head)
	}

	// Borrow the objects of the inputs, then copy in what the refs reach.
	alternates := filepath.Join(o.Path, ".git", "objects", "info", "alternates")
	objects := make([]string, 0, len(g))
	for _, in := range g {
		bs, err := git("-C", in.path, "rev-parse", "--path-format=absolute", "--git-path", "objects")
		if err != nil {
			return 0, 0, errors.Wrapf(err, "locate objects of %s", in.path)
		}
		objects = append(objects, strings.TrimSpace(string(bs)))
	}
	if err := os.WriteFile(alternates, fmt.Appendf(nil, "%s\n", strings.Join(objects, "\n")), 0644); err != nil {
		return 0, 0, errors.Wrapf(err, "write %s", alternates)
	}

	refs, err := g.refs()
	if err != nil {
		return 0, 0, errors.Wrap(err, "collect refs")
	}
	creates := make([]string, 0, len(refs))
	for _, name := range slices.Sorted(maps.Keys(refs)) {
		creates = append(creates, fmt.Sprintf("create %s %s", name, refs[name]))
	}
	if err := gitWithStdin(fmt.Sprintf("%s\n", strings.Join(creates, "\n")), "-C", o.Path, "update-ref", "--stdin"); err != nil {
		return 0, 0, errors.Wrap(err, "create refs")
	}

	if len(o.Shallow) > 0 {
		if err := os.WriteFile(filepath.Join(o.Path, ".git", "shallow"), fmt.Appendf(nil, "%s\n", strings.Join(o.Shallow, "\n")), 0644); err != nil {
			return 0, 0, errors.Wrapf(err, "write %s", filepath.Join(o.Path, ".git", "shallow"))
		}
	}

	if last.origin != "" {
		if _, err := git("-C", o.Path, "remote", "add", "origin", last.origin); err != nil {
			return 0, 0, errors.Wrapf(err, "add origin %s", last.origin)
		}
	}

	// Without -l, repack copies the borrowed objects into a pack of its own.
	if _, err := git("-C", o.Path, "repack", "-a", "-d", "--quiet"); err != nil {
		return 0, 0, errors.Wrap(err, "repack")
	}
	if err := os.Remove(alternates); err != nil {
		return 0, 0, errors.Wrapf(err, "remove %s", alternates)
	}

	if _, err := git("-C", o.Path, "fsck", "--connectivity-only", "--no-dangling", "--no-progress"); err != nil {
		return 0, 0, errors.Wrap(err, "fsck")
	}
	bs, err := git("-C", o.Path, "rev-list", "--count", "--branches", "--tags")
	if err != nil {
		return 0, 0, errors.Wrap(err, "count commits")
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(bs)))
	if err != nil {
		return 0, 0, errors.Wrapf(err, "parse %q", bs)
	}
	if n != o.Commits {
		return 0, 0, errors.Errorf("unexpected number of commits. expected: %d, actual: %d", o.Commits, n)
	}

	// Without an index, git sees every file as deleted, and pull --restore
	// has nothing to restore from.
	if _, err := git("-C", o.Path, "reset", "--quiet"); err != nil {
		return 0, 0, errors.Wrap(err, "reset")
	}

	var pack, dotgit int64
	if err := filepath.WalkDir(filepath.Join(o.Path, ".git"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return errors.Wrapf(err, "get info %s", path)
		}
		dotgit += info.Size()
		if filepath.Dir(path) == filepath.Join(o.Path, ".git", "objects", "pack") && filepath.Ext(path) == ".pack" {
			pack += info.Size()
		}
		return nil
	}); err != nil {
		return 0, 0, errors.Wrapf(err, "walk %s", filepath.Join(o.Path, ".git"))
	}

	return pack, dotgit, nil
}

// refs is the branches of the last input, the tags of every input, and a tag
// at each input's branch tips.
func (g group) refs() (map[string]string, error) {
	refs := make(map[string]string)
	add := func(name, oid string) error {
		if v, ok := refs[name]; ok && v != oid {
			return errors.Errorf("unexpected object of %s. expected: %s, actual: %s", name, v, oid)
		}
		refs[name] = oid
		return nil
	}

	for _, in := range g {
		for name, oid := range in.refs {
			switch {
			case strings.HasPrefix(name, "refs/tags/"):
				if err := add(name, oid); err != nil {
					return nil, errors.Wrapf(err, "tag of %s", in.path)
				}
			default:
				if b, ok := strings.CutPrefix(name, "refs/heads/"); ok {
					if err := add(fmt.Sprintf("refs/tags/%s/%s", filepath.Base(in.path), b), oid); err != nil {
						return nil, errors.Wrapf(err, "branch tip of %s", in.path)
					}
				}
			}
		}
	}

	for name, oid := range g[len(g)-1].refs {
		if strings.HasPrefix(name, "refs/heads/") {
			refs[name] = oid
		}
	}

	return refs, nil
}

func diskUsage(dir string, revs ...string) (int64, error) {
	bs, err := git(append([]string{"-C", dir, "rev-list", "--objects", "--disk-usage"}, revs...)...)
	if err != nil {
		return 0, errors.Wrap(err, "rev-list")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(string(bs)), 10, 64)
	if err != nil {
		return 0, errors.Wrapf(err, "parse %q", bs)
	}

	return n, nil
}

func git(args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Stderr = &stderr
	bs, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "exec %q, stderr: %q", cmd.String(), stderr.String())
	}
	return bs, nil
}

func gitWithStdin(stdin string, args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "exec %q, stderr: %q", cmd.String(), stderr.String())
	}
	return nil
}
