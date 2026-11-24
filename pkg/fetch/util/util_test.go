package util_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

func TestUnique(t *testing.T) {
	type test[T comparable] struct {
		name string
		args []T
		want []T
	}
	tests := []test[int]{
		{
			name: "int",
			args: []int{1, 1, 2},
			want: []int{1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, util.Unique(tt.args), cmpopts.SortSlices(func(i, j int) bool { return i < j })); diff != "" {
				t.Errorf("Unique(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestRemoveAll(t *testing.T) {
	type args struct {
		root string
		opts []util.RemoveOption
	}
	tests := []struct {
		name string
		args args
		// entries are created directly under root before the call; each is a
		// directory when it ends in "/" and a file otherwise. siblings are
		// created beside root the same way, and the call must leave them all.
		entries  []string
		siblings []string
		// missing leaves root uncreated, and file creates it as an empty file
		// rather than a directory.
		missing bool
		file    bool
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				root: "happy",
			},
			entries: []string{".git/", "test.json"},
			want:    []string{".git"},
		},
		{
			// As before a first fetch.
			name: "root that does not exist",
			args: args{
				root: "missing",
			},
			missing: true,
		},
		{
			// An empty root is the directory the call is made from.
			name: "empty root",
			args: args{
				root: "",
			},
			entries: []string{".git/", "test.json"},
			want:    []string{".git"},
		},
		{
			// root is cleaned as every write under it is: missing/../out is
			// out, though missing does not exist.
			name: "root that is not clean",
			args: args{
				root: "missing/../out",
			},
			entries: []string{".git/", "test.json"},
			want:    []string{".git"},
		},
		{
			// Unlike a missing root, one that cannot be read is an error, or
			// the run would go on over a tree that was never emptied.
			name: "root that is a file",
			args: args{
				root: "file",
			},
			file:    true,
			wantErr: true,
		},
		{
			// root is a path, not a pattern: out[1] must not reach out1.
			name: "root holding a character class",
			args: args{
				root: "out[1]",
			},
			entries:  []string{".git/", "test.json"},
			siblings: []string{"out1/", "out1/test.json"},
			want:     []string{".git"},
		},
		{
			name: "root holding a star",
			args: args{
				root: "out*",
			},
			entries:  []string{".git/", "test.json"},
			siblings: []string{"out-a/", "out-a/test.json"},
			want:     []string{".git"},
		},
		{
			name: "root holding an unclosed bracket",
			args: args{
				root: "out[",
			},
			entries: []string{".git/", "test.json"},
			want:    []string{".git"},
		},
		{
			// The option states the whole set, so .git has to be named to
			// survive alongside what the call adds.
			name: "keep",
			args: args{
				root: "keep",
				opts: []util.RemoveOption{util.WithKeep(".git", "raw")},
			},
			entries: []string{".git/", "raw/", "origin/", ".claude/", "test.json"},
			want:    []string{".git", "raw"},
		},
		{
			// Which is also what makes .git droppable, the one way to empty a
			// tree completely.
			name: "keep nothing",
			args: args{
				root: "nothing",
				opts: []util.RemoveOption{util.WithKeep()},
			},
			entries: []string{".git/", "raw/", "test.json"},
			want:    []string{},
		},
		{
			// Repeating the option replaces rather than accumulates.
			name: "last option wins",
			args: args{
				root: "last",
				opts: []util.RemoveOption{util.WithKeep(".git"), util.WithKeep("raw")},
			},
			entries: []string{".git/", "raw/", "test.json"},
			want:    []string{"raw"},
		},
		{
			// A kept name is the entry's own name, not a suffix of it: keeping
			// "raw" must not spare "rawdata".
			name: "keep is not a suffix match",
			args: args{
				root: "keep-exact",
				opts: []util.RemoveOption{util.WithKeep("raw")},
			},
			entries: []string{"raw/", "rawdata/", "vuls-data-raw/"},
			want:    []string{"raw"},
		},
		{
			// Same for the implicit .git.
			name: "git is not a suffix match",
			args: args{
				root: "git-exact",
			},
			entries: []string{".git/", "bare.git/"},
			want:    []string{".git"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// root is given relative to the directory the call is made from,
			// as a --dir typed on the command line is.
			parent := t.TempDir()
			t.Chdir(parent)

			d := filepath.Join(parent, tt.args.root)
			switch {
			case tt.missing:
				// Left uncreated.
			case tt.file:
				f, err := os.Create(d)
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				f.Close()
			default:
				if err := os.MkdirAll(d, 0750); err != nil {
					t.Fatal("unexpected error:", err)
				}
			}

			for _, tree := range []struct {
				dir     string
				entries []string
			}{{dir: d, entries: tt.entries}, {dir: parent, entries: tt.siblings}} {
				for _, e := range tree.entries {
					if name, ok := strings.CutSuffix(e, "/"); ok {
						if err := os.Mkdir(filepath.Join(tree.dir, name), 0750); err != nil {
							t.Fatal("unexpected error:", err)
						}
						continue
					}
					f, err := os.Create(filepath.Join(tree.dir, e))
					if err != nil {
						t.Fatal("unexpected error:", err)
					}
					f.Close()
				}
			}

			if err := util.RemoveAll(tt.args.root, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("RemoveAll() error = %v, wantErr %v", err, tt.wantErr)
			}

			for _, s := range tt.siblings {
				if _, err := os.Lstat(filepath.Join(parent, s)); err != nil {
					t.Errorf("RemoveAll() reached %s beside root. err: %v", s, err)
				}
			}

			if tt.missing || tt.wantErr {
				return
			}

			es, err := os.ReadDir(d)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			got := make([]string, 0, len(es))
			for _, e := range es {
				got = append(got, e.Name())
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(x, y string) bool { return x < y })); diff != "" {
				t.Errorf("RemoveAll(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestEnsureWritten(t *testing.T) {
	type args struct {
		root string
		opts []util.EnsureOption
	}
	tests := []struct {
		name string
		args args
		// entries are created under root before the call, with their parents;
		// each is a directory when it ends in "/" and a file otherwise. A case
		// with no entries leaves root itself uncreated.
		entries []string
		// link makes root a symbolic link to the directory the entries are
		// created in, as a --dir given as a link is.
		link bool
		// links are names under root made symbolic links to a directory
		// outside root, which holds outside, created like entries.
		links   []string
		outside []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				root: "happy",
			},
			entries: []string{".git/", ".git/HEAD", "2024/CVE-2024-0001.json"},
		},
		{
			// RemoveAll and util.Write go through a root that is a link, so the
			// check has to see the tree it points at too.
			name: "root is a symbolic link",
			args: args{
				root: "link",
				opts: []util.EnsureOption{util.WithRequire("2024")},
			},
			entries: []string{".git/", ".git/HEAD", "2024/CVE-2024-0001.json"},
			link:    true,
		},
		{
			name: "root is a symbolic link to nothing",
			args: args{
				root: "dangling",
			},
			link:    true,
			wantErr: true,
		},
		{
			// Only root itself is followed. A link below it is not a file the
			// fetch wrote, whatever it points at.
			name: "a link under root is not output",
			args: args{
				root: "link-below",
			},
			entries: []string{".git/", ".git/HEAD"},
			links:   []string{"2024"},
			outside: []string{"CVE-2024-0001.json"},
			wantErr: true,
		},
		{
			// .git is history, not output: a tree holding only it was left
			// as RemoveAll found it.
			name: "only .git",
			args: args{
				root: "only-git",
			},
			entries: []string{".git/", ".git/HEAD"},
			wantErr: true,
		},
		{
			name: "root missing",
			args: args{
				root: "missing",
			},
			wantErr: true,
		},
		{
			// A directory is not a file: unpacking or cloning can leave empty
			// ones behind without writing anything.
			name: "empty directories only",
			args: args{
				root: "empty-dirs",
			},
			entries: []string{"2024/", "2025/nested/"},
			wantErr: true,
		},
		{
			// What RemoveAll kept is no more output than .git is.
			name: "kept tree ignored",
			args: args{
				root: "ignore-kept",
				opts: []util.EnsureOption{util.WithIgnore(".git", "raw")},
			},
			entries: []string{".git/", ".git/HEAD", "raw/", "raw/advisory.json"},
			wantErr: true,
		},
		{
			// Nor is a file written whatever the fetch got.
			name: "readme ignored",
			args: args{
				root: "ignore-readme",
				opts: []util.EnsureOption{util.WithIgnore(".git", "README.md")},
			},
			entries: []string{".git/", ".git/HEAD", "README.md"},
			wantErr: true,
		},
		{
			// As in WithKeep, an ignored name is the entry's own name directly
			// under root: "rawdata" and a nested "raw" are output.
			name: "ignore is matched by name directly under root",
			args: args{
				root: "ignore-exact",
				opts: []util.EnsureOption{util.WithIgnore(".git", "raw")},
			},
			entries: []string{"raw/", "raw/advisory.json", "rawdata/", "nested/raw/advisory.json"},
		},
		{
			// The option states the whole set, so .git counts unless named.
			name: "ignore replaces the default",
			args: args{
				root: "ignore-replaces",
				opts: []util.EnsureOption{util.WithIgnore("README.md")},
			},
			entries: []string{".git/", ".git/HEAD"},
		},
		{
			name: "required sections written",
			args: args{
				root: "required",
				opts: []util.EnsureOption{util.WithRequire("weakness", "category", "view")},
			},
			entries: []string{"weakness/79.json", "category/1027.json", "view/1026.json"},
		},
		{
			// The default check passes on the other sections; only naming the
			// section catches the one that stopped being written.
			name: "required section missing",
			args: args{
				root: "required-missing",
				opts: []util.EnsureOption{util.WithRequire("weakness", "category", "view")},
			},
			entries: []string{"weakness/79.json", "view/1026.json"},
			wantErr: true,
		},
		{
			name: "required section empty",
			args: args{
				root: "required-empty",
				opts: []util.EnsureOption{util.WithRequire("weakness", "category", "view")},
			},
			entries: []string{"weakness/79.json", "category/", "view/1026.json"},
			wantErr: true,
		},
		{
			name: "required path nested and a file",
			args: args{
				root: "required-nested",
				opts: []util.EnsureOption{util.WithRequire(filepath.Join("9", "definitions"), "repository-to-cpe.json")},
			},
			entries: []string{"9/definitions/definition.json", "repository-to-cpe.json"},
		},
		{
			name: "required path outside root",
			args: args{
				root: "required-outside",
				opts: []util.EnsureOption{util.WithRequire(filepath.Join("..", "outside"))},
			},
			entries: []string{"weakness/79.json"},
			wantErr: true,
		},
		{
			// A required section is no exception: a link would let files
			// outside root stand in for it.
			name: "required section is a symbolic link",
			args: args{
				root: "required-link",
				opts: []util.EnsureOption{util.WithRequire("origin")},
			},
			entries: []string{"weakness/79.json"},
			links:   []string{"origin"},
			outside: []string{"advisory.json"},
			wantErr: true,
		},
		{
			// Nor is a directory on the way to one, which the system follows
			// even where the last element is not.
			name: "required path through a linked directory",
			args: args{
				root: "required-link-parent",
				opts: []util.EnsureOption{util.WithRequire(filepath.Join("9", "definitions"))},
			},
			entries: []string{"repository-to-cpe.json"},
			links:   []string{"9"},
			outside: []string{"definitions/definition.json"},
			wantErr: true,
		},
		{
			// A run that is one part of a whole can rightly fetch nothing.
			name: "empty allowed",
			args: args{
				root: "allow-empty",
				opts: []util.EnsureOption{util.WithAllowEmpty(true)},
			},
			entries: []string{".git/", ".git/HEAD"},
		},
		{
			name: "empty allowed, root missing",
			args: args{
				root: "allow-empty-missing",
				opts: []util.EnsureOption{util.WithAllowEmpty(true)},
			},
		},
		{
			// Nothing written passes whatever sections are required...
			name: "empty allowed over required sections",
			args: args{
				root: "allow-empty-required",
				opts: []util.EnsureOption{util.WithAllowEmpty(true), util.WithRequire("weakness", "category", "view")},
			},
			entries: []string{".git/", ".git/HEAD"},
		},
		{
			// ...but something written is held to them: fetching part of what
			// should have been fetched is not fetching nothing.
			name: "empty allowed, required section missing",
			args: args{
				root: "allow-empty-partial",
				opts: []util.EnsureOption{util.WithAllowEmpty(true), util.WithRequire("weakness", "category", "view")},
			},
			entries: []string{"weakness/79.json", "view/1026.json"},
			wantErr: true,
		},
		{
			// A required path outside root is a mistake in the call, so
			// allowing nothing written does not let it pass.
			name: "empty allowed, required path outside root",
			args: args{
				root: "allow-empty-outside",
				opts: []util.EnsureOption{util.WithAllowEmpty(true), util.WithRequire(filepath.Join("..", "outside"))},
			},
			entries: []string{".git/", ".git/HEAD"},
			wantErr: true,
		},
		{
			name: "empty not allowed",
			args: args{
				root: "disallow-empty",
				opts: []util.EnsureOption{util.WithAllowEmpty(false)},
			},
			entries: []string{".git/", ".git/HEAD"},
			wantErr: true,
		},
		{
			// Repeating the option replaces rather than accumulates.
			name: "last require wins",
			args: args{
				root: "required-last",
				opts: []util.EnsureOption{util.WithRequire("category"), util.WithRequire("weakness")},
			},
			entries: []string{"weakness/79.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := filepath.Join(t.TempDir(), tt.args.root)
			root := d
			if tt.link {
				root = filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(d, root); err != nil {
					t.Fatal("unexpected error:", err)
				}
			}

			outside := filepath.Join(t.TempDir(), "outside")
			for _, tree := range []struct {
				dir     string
				entries []string
			}{{dir: d, entries: tt.entries}, {dir: outside, entries: tt.outside}} {
				for _, e := range tree.entries {
					if name, ok := strings.CutSuffix(e, "/"); ok {
						if err := os.MkdirAll(filepath.Join(tree.dir, name), 0750); err != nil {
							t.Fatal("unexpected error:", err)
						}
						continue
					}
					if err := os.MkdirAll(filepath.Dir(filepath.Join(tree.dir, e)), 0750); err != nil {
						t.Fatal("unexpected error:", err)
					}
					f, err := os.Create(filepath.Join(tree.dir, e))
					if err != nil {
						t.Fatal("unexpected error:", err)
					}
					f.Close()
				}
			}
			for _, l := range tt.links {
				if err := os.Symlink(outside, filepath.Join(d, l)); err != nil {
					t.Fatal("unexpected error:", err)
				}
			}

			if err := util.EnsureWritten(root, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("EnsureWritten() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSplit(t *testing.T) {
	type args struct {
		str        string
		delimiters []string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "",
			args: args{
				str:        "a-b-c",
				delimiters: []string{"-"},
			},
			want: []string{"a", "b-c"},
		},
		{
			name: "",
			args: args{
				str:        "a-b:c",
				delimiters: []string{"-", ":"},
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "",
			args: args{
				str:        "a-b:c",
				delimiters: []string{":", "-"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.Split(tt.args.str, tt.args.delimiters...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Split() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(i, j int) bool { return i < j })); diff != "" {
				t.Errorf("Split(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestWrite(t *testing.T) {
	type content struct {
		Message string `json:"message,omitempty"`
	}
	type args struct {
		path    string
		content any
		opts    []util.WriteOption
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				path:    "test.json",
				content: content{Message: "hello"},
			},
			want: []byte("{\n\t\"message\": \"hello\"\n}"),
		},
		{
			name: "invalid utf-8",
			args: args{
				path:    "test.json",
				content: content{Message: string([]byte{0x66, 0xfc, 0x72})},
			},
			want:    []byte{},
			wantErr: true,
		},
		{
			name: "allow invalid utf-8",
			args: args{
				path:    "test.json",
				content: content{Message: string([]byte{0x66, 0xfc, 0x72})},
				opts:    []util.WriteOption{util.WithAllowInvalidUTF8(true)},
			},
			want: fmt.Appendf(nil, "{\n\t\"message\": \"%s\"\n}", string([]byte{0x66, 0xef, 0xbf, 0xbd, 0x72})),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.args.path)
			if err := util.Write(path, tt.args.content, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("Write() error = %v, wantErr %v", err, tt.wantErr)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Write(). (-expected +got):\n%s", diff)
			}
		})
	}
}
