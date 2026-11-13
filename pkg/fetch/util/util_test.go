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
		// directory when it ends in "/" and a file otherwise.
		entries []string
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
			d := filepath.Join(t.TempDir(), tt.args.root)
			if err := os.MkdirAll(d, 0750); err != nil {
				t.Fatal("unexpected error:", err)
			}

			for _, e := range tt.entries {
				if name, ok := strings.CutSuffix(e, "/"); ok {
					if err := os.Mkdir(filepath.Join(d, name), 0750); err != nil {
						t.Fatal("unexpected error:", err)
					}
					continue
				}
				f, err := os.Create(filepath.Join(d, e))
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				f.Close()
			}

			if err := util.RemoveAll(d, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("RemoveAll() error = %v, wantErr %v", err, tt.wantErr)
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
			name: "kept entries are not output",
			args: args{
				root: "kept",
				opts: []util.EnsureOption{util.WithKeep(".git", "raw")},
			},
			entries: []string{".git/", ".git/HEAD", "raw/", "raw/advisory.json"},
			wantErr: true,
		},
		{
			// As in RemoveAll, a kept name is the entry's own name directly
			// under root: "rawdata" and a nested "raw" are output.
			name: "keep is matched by name directly under root",
			args: args{
				root: "kept-exact",
				opts: []util.EnsureOption{util.WithKeep(".git", "raw")},
			},
			entries: []string{"raw/", "raw/advisory.json", "rawdata/", "nested/raw/advisory.json"},
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
			// Nothing written passes whatever is required...
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

			for _, e := range tt.entries {
				if name, ok := strings.CutSuffix(e, "/"); ok {
					if err := os.MkdirAll(filepath.Join(d, name), 0750); err != nil {
						t.Fatal("unexpected error:", err)
					}
					continue
				}
				if err := os.MkdirAll(filepath.Dir(filepath.Join(d, e)), 0750); err != nil {
					t.Fatal("unexpected error:", err)
				}
				f, err := os.Create(filepath.Join(d, e))
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				f.Close()
			}

			if err := util.EnsureWritten(d, tt.args.opts...); (err != nil) != tt.wantErr {
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
