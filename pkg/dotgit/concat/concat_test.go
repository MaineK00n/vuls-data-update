package concat_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/concat"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util/test/git"
)

// An archive of the 5-commit fixture: the depth commits up to tip, both
// 1-based. a1 holds commits 1-2 and is not shallow, as its depth goes past
// the first commit (at exactly 2, git marks commit 1 shallow), a2 holds 2-4
// with 2 shallow, d4 only 4 with 4 shallow (an archive of a repository of one
// commit), and a3 4-5 with 4 shallow.
type archive struct {
	name  string
	tip   int
	depth int
}

var (
	a1 = archive{name: "vuls-data-raw-test-archive-1", tip: 2, depth: 3}
	a2 = archive{name: "vuls-data-raw-test-archive-2", tip: 4, depth: 3}
	d4 = archive{name: "vuls-data-raw-test-archive-3", tip: 4, depth: 1}
	a3 = archive{name: "vuls-data-raw-test-archive-4", tip: 5, depth: 2}
)

func TestConcat(t *testing.T) {
	type args struct {
		archives []archive
		maxSize  int64
		dryRun   bool
		exists   bool
	}
	type output struct {
		name    string
		made    bool
		inputs  []string
		commits int
		shallow []int
		refs    map[string]int
	}
	tests := []struct {
		name     string
		args     args
		want     []output
		hasError bool
	}{
		{
			name: "join a chain",
			args: args{
				archives: []archive{a1, a2, a3},
			},
			want: []output{
				{
					name:    a3.name,
					made:    true,
					inputs:  []string{a1.name, a2.name, a3.name},
					commits: 5,
					refs: map[string]int{
						"refs/heads/main":                         5,
						fmt.Sprintf("refs/tags/%s/main", a1.name): 2,
						fmt.Sprintf("refs/tags/%s/main", a2.name): 4,
						fmt.Sprintf("refs/tags/%s/main", a3.name): 5,
					},
				},
			},
		},
		{
			name: "start from a shallow archive",
			args: args{
				archives: []archive{a2, a3},
			},
			want: []output{
				{
					name:    a3.name,
					made:    true,
					inputs:  []string{a2.name, a3.name},
					commits: 4,
					shallow: []int{2},
					refs: map[string]int{
						"refs/heads/main":                         5,
						fmt.Sprintf("refs/tags/%s/main", a2.name): 4,
						fmt.Sprintf("refs/tags/%s/main", a3.name): 5,
					},
				},
			},
		},
		{
			name: "an archive of one commit in between",
			args: args{
				archives: []archive{a2, d4, a3},
			},
			want: []output{
				{
					name:    a3.name,
					made:    true,
					inputs:  []string{a2.name, d4.name, a3.name},
					commits: 4,
					shallow: []int{2},
					refs: map[string]int{
						"refs/heads/main":                         5,
						fmt.Sprintf("refs/tags/%s/main", a2.name): 4,
						fmt.Sprintf("refs/tags/%s/main", d4.name): 4,
						fmt.Sprintf("refs/tags/%s/main", a3.name): 5,
					},
				},
			},
		},
		{
			name: "start from an archive of one commit",
			args: args{
				archives: []archive{d4, a3},
			},
			want: []output{
				{
					name:    a3.name,
					made:    true,
					inputs:  []string{d4.name, a3.name},
					commits: 2,
					shallow: []int{4},
					refs: map[string]int{
						"refs/heads/main":                         5,
						fmt.Sprintf("refs/tags/%s/main", d4.name): 4,
						fmt.Sprintf("refs/tags/%s/main", a3.name): 5,
					},
				},
			},
		},
		{
			name: "dry run",
			args: args{
				archives: []archive{a1, a2, a3},
				dryRun:   true,
			},
			want: []output{
				{
					name:    a3.name,
					inputs:  []string{a1.name, a2.name, a3.name},
					commits: 5,
				},
			},
		},
		{
			name: "split to one archive each",
			args: args{
				archives: []archive{a1, a2, a3},
				maxSize:  1,
			},
			want: []output{
				{
					name:    a1.name,
					inputs:  []string{a1.name},
					commits: 2,
				},
				{
					name:    a2.name,
					inputs:  []string{a2.name},
					commits: 3,
					shallow: []int{2},
				},
				{
					name:    a3.name,
					inputs:  []string{a3.name},
					commits: 2,
					shallow: []int{4},
				},
			},
		},
		{
			name: "gap",
			args: args{
				archives: []archive{a1, a3},
			},
			hasError: true,
		},
		{
			name: "already exists",
			args: args{
				archives: []archive{a1, a2},
				exists:   true,
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			src, err := git.Populate(dir, "testdata/fixtures/history")
			if err != nil {
				t.Fatalf("populate. err: %v", err)
			}
			hashes, err := git.CommitHashes(src)
			if err != nil {
				t.Fatalf("commit hashes. err: %v", err)
			}

			repositories := make([]string, 0, len(tt.args.archives))
			for _, a := range tt.args.archives {
				branch := fmt.Sprintf("tmp-%s", a.name)
				run(t, "-C", src, "branch", "--force", branch, hashes[a.tip-1])
				path := filepath.Join(dir, "archives", a.name)
				run(t, "clone", "--quiet", "--depth", strconv.Itoa(a.depth), "--single-branch", "--no-tags", "--no-checkout", "--branch", branch, fmt.Sprintf("file://%s", src), path)
				run(t, "-C", path, "branch", "--move", branch, "main")
				run(t, "-C", path, "remote", "set-url", "origin", "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test")
				repositories = append(repositories, path)
			}
			if tt.args.exists {
				if err := os.MkdirAll(filepath.Join(dir, "joined", tt.args.archives[len(tt.args.archives)-1].name), 0755); err != nil {
					t.Fatalf("mkdir. err: %v", err)
				}
			}

			got, err := concat.Concat(repositories, concat.WithDir(filepath.Join(dir, "joined")), concat.WithMaxSize(tt.args.maxSize), concat.WithDryRun(tt.args.dryRun))
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				if len(got) != len(tt.want) {
					t.Fatalf("number of outputs. expected: %d, actual: %d", len(tt.want), len(got))
				}
				for i, w := range tt.want {
					g := got[i]

					inputs := make([]string, 0, len(g.Inputs))
					for _, in := range g.Inputs {
						inputs = append(inputs, filepath.Base(in))
					}
					var shallow []string
					for _, s := range w.shallow {
						shallow = append(shallow, hashes[s-1])
					}
					if diff := cmp.Diff(struct {
						Name    string
						Inputs  []string
						Commits int
						Shallow []string
					}{w.name, w.inputs, w.commits, shallow}, struct {
						Name    string
						Inputs  []string
						Commits int
						Shallow []string
					}{g.Name, inputs, g.Commits, g.Shallow}); diff != "" {
						t.Errorf("output %d. (-expected +got):\n%s", i, diff)
					}

					if g.Size.Predicted <= 0 {
						t.Errorf("output %d. predicted size: %d", i, g.Size.Predicted)
					}

					if len(w.inputs) > 1 {
						if want := filepath.Join(dir, "joined", w.name); g.Path != want {
							t.Errorf("output %d. path. expected: %q, actual: %q", i, want, g.Path)
						}
					} else if g.Path != "" {
						t.Errorf("output %d. path. expected: none, actual: %q", i, g.Path)
					}

					_, err := os.Stat(filepath.Join(dir, "joined", w.name))
					switch {
					case w.made && err != nil:
						t.Errorf("output %d. stat. err: %v", i, err)
					case !w.made && !errors.Is(err, fs.ErrNotExist):
						t.Errorf("output %d. expected nothing made, stat. err: %v", i, err)
					}
					if !w.made {
						continue
					}

					if g.Size.Pack <= 0 || g.Size.Pack > g.Size.DotGit {
						t.Errorf("output %d. pack size: %d, .git size: %d", i, g.Size.Pack, g.Size.DotGit)
					}

					refs := make(map[string]string)
					for line := range strings.Lines(run(t, "-C", g.Path, "for-each-ref", "--format=%(refname) %(objectname)")) {
						name, oid, _ := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
						refs[name] = oid
					}
					wantRefs := make(map[string]string)
					for name, c := range w.refs {
						wantRefs[name] = hashes[c-1]
					}
					if diff := cmp.Diff(wantRefs, refs); diff != "" {
						t.Errorf("output %d. refs. (-expected +got):\n%s", i, diff)
					}

					if _, err := os.Stat(filepath.Join(g.Path, ".git", "objects", "info", "alternates")); !errors.Is(err, fs.ErrNotExist) {
						t.Errorf("output %d. alternates left. stat. err: %v", i, err)
					}

					if origin := strings.TrimSpace(run(t, "-C", g.Path, "config", "--get", "remote.origin.url")); origin != "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test" {
						t.Errorf("output %d. origin: %q", i, origin)
					}

					if files := run(t, "-C", g.Path, "ls-files"); files != "README.md\n" {
						t.Errorf("output %d. index. expected: %q, actual: %q", i, "README.md\n", files)
					}
				}
			}
		})
	}
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	bs, err := cmd.Output()
	if err != nil {
		t.Fatalf("exec %q. err: %v", cmd.String(), err)
	}
	return string(bs)
}
