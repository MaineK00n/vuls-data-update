package find_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/find"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestFind(t *testing.T) {
	type args struct {
		repository string
		expression string
		opts       []find.Option
	}
	tests := []struct {
		name     string
		args     args
		want     []find.FileObject
		hasError bool
	}{
		{
			name: ".*\\.md, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.md",
				opts:       []find.Option{find.WithUseNativeGit(true), find.WithTreeish("main")},
			},
			want: []find.FileObject{
				{
					Name: "README.md",
					Mode: "100644",
					Type: "blob",
					Hash: "46df57e1de336181a027385cf5ce993bba78db3a",
					Size: 21,
				},
			},
		},
		{
			name: ".*\\.md, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.md",
				opts:       []find.Option{find.WithUseNativeGit(false), find.WithTreeish("main")},
			},
			want: []find.FileObject{
				{
					Name: "README.md",
					Mode: "0100644",
					Type: "blob",
					Hash: "46df57e1de336181a027385cf5ce993bba78db3a",
					Size: 21,
				},
			},
		},
		{
			name: ".*\\.md, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.md",
				opts:       []find.Option{find.WithUseNativeGit(true), find.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab")},
			},
			want: []find.FileObject{
				{
					Name: "README.md",
					Mode: "100644",
					Type: "blob",
					Hash: "46df57e1de336181a027385cf5ce993bba78db3a",
					Size: 21,
				},
			},
		},
		{
			name: ".*\\.md, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.md",
				opts:       []find.Option{find.WithUseNativeGit(false), find.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab")},
			},
			want: []find.FileObject{
				{
					Name: "README.md",
					Mode: "0100644",
					Type: "blob",
					Hash: "46df57e1de336181a027385cf5ce993bba78db3a",
					Size: 21,
				},
			},
		},
		{
			name: ".*\\.json, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.json",
				opts:       []find.Option{find.WithUseNativeGit(true), find.WithTreeish("main")},
			},
			want: nil,
		},
		{
			name: ".*\\.json, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.json",
				opts:       []find.Option{find.WithUseNativeGit(false), find.WithTreeish("main")},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.args.repository)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.args.repository, err)
			}
			defer f.Close()

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.args.repository, err)
			}

			got, err := find.Find(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst")), tt.args.expression, tt.args.opts...)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Find(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

// TestFindTreeish finds in tree-ish forms other than a commit's name, whose
// parts go-git skips: with them, the go-git path would search the top tree of
// the commit.
func TestFindTreeish(t *testing.T) {
	type args struct {
		expression string
		opts       []find.Option
	}
	tests := []struct {
		name string
		args args
		want []find.FileObject
		// wantErr is the error in full, and wantErrIs a cause it wraps.
		wantErr   string
		wantErrIs error
	}{
		{
			name: "directory in a branch, native git",
			args: args{
				expression: `.*\.json`,
				opts:       []find.Option{find.WithUseNativeGit(true), find.WithTreeish("main:dir")},
			},
			want: []find.FileObject{
				{
					Name: "b.json",
					Mode: "100644",
					Type: "blob",
					Hash: "4ab0028f19917e952d636a873fd73b9f6c009a44",
					Size: 13,
				},
			},
		},
		{
			// go-git skips :dir, and would search the top tree, with a.json.
			name: "directory in a branch, go-git",
			args: args{
				expression: `.*\.json`,
				opts:       []find.Option{find.WithUseNativeGit(false), find.WithTreeish("main:dir")},
			},
			wantErr:   `resolve main:dir: go-git does not support ":dir" in "main:dir", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name: "tree of a branch, native git",
			args: args{
				expression: `.*\.json`,
				opts:       []find.Option{find.WithUseNativeGit(true), find.WithTreeish("main^{tree}")},
			},
			want: []find.FileObject{
				{
					Name: "a.json",
					Mode: "100644",
					Type: "blob",
					Hash: "2c67f53906511994bf248a2f8502df934d097f2c",
					Size: 13,
				},
				{
					Name: "dir/b.json",
					Mode: "100644",
					Type: "blob",
					Hash: "4ab0028f19917e952d636a873fd73b9f6c009a44",
					Size: 13,
				},
			},
		},
		{
			// go-git skips ^{tree}. Here it would search the same tree, but
			// ^{tree} is refused for every caller.
			name: "tree of a branch, go-git",
			args: args{
				expression: `.*\.json`,
				opts:       []find.Option{find.WithUseNativeGit(false), find.WithTreeish("main^{tree}")},
			},
			wantErr:   `resolve main^{tree}: go-git does not support "^{tree}" in "main^{tree}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := find.Find(newRepository(t), tt.args.expression, tt.args.opts...)
			switch {
			case err != nil && tt.wantErr == "":
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.wantErr != "":
				t.Errorf("expected error has not occurred. want: %q", tt.wantErr)
			case err != nil:
				if err.Error() != tt.wantErr {
					t.Errorf("unexpected err. expected: %q, actual: %q", tt.wantErr, err)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("unexpected err. expected it to wrap %q, actual: %q", tt.wantErrIs, err)
				}
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Find(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

// newRepository makes a repository whose main has a.json in its top tree and
// b.json in dir.
func newRepository(t *testing.T) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "vuls-data-raw-test")
	git(t, "", "init", "--quiet", "--initial-branch=main", dir)
	for _, o := range []struct {
		content string
		hash    string
	}{
		{
			// a.json
			content: `{"name":"a"}
`,
			hash: "2c67f53906511994bf248a2f8502df934d097f2c",
		},
		{
			// dir/b.json
			content: `{"name":"b"}
`,
			hash: "4ab0028f19917e952d636a873fd73b9f6c009a44",
		},
	} {
		if got := git(t, o.content, "-C", dir, "hash-object", "-t", "blob", "-w", "--stdin"); got != o.hash {
			t.Fatalf("hash-object -t blob. expected: %s, actual: %s", o.hash, got)
		}
	}
	git(t, "", "-C", dir, "update-index", "--add", "--cacheinfo", "100644,2c67f53906511994bf248a2f8502df934d097f2c,a.json", "--cacheinfo", "100644,4ab0028f19917e952d636a873fd73b9f6c009a44,dir/b.json")
	if got := git(t, "", "-C", dir, "write-tree"); got != "60affd23804504816b8d17e5e49d94f1519b5868" {
		t.Fatalf("write-tree. expected: %s, actual: %s", "60affd23804504816b8d17e5e49d94f1519b5868", got)
	}
	if got := git(t, `tree 60affd23804504816b8d17e5e49d94f1519b5868
author A U Thor <author@example.com> 1700000000 +0000
committer C O Mitter <committer@example.com> 1700000000 +0000

initial
`, "-C", dir, "hash-object", "-t", "commit", "-w", "--stdin"); got != "dd0e7bbc036609aadfdde8337ccf54ada40512ad" {
		t.Fatalf("hash-object -t commit. expected: %s, actual: %s", "dd0e7bbc036609aadfdde8337ccf54ada40512ad", got)
	}
	git(t, "", "-C", dir, "update-ref", "refs/heads/main", "dd0e7bbc036609aadfdde8337ccf54ada40512ad")

	return dir
}

func git(t *testing.T, stdin string, args ...string) string {
	t.Helper()

	bs, err := util.GitWithStdin(strings.NewReader(stdin), args...)
	if err != nil {
		t.Fatalf("git %q. err: %v", args, err)
	}
	return strings.TrimSpace(string(bs))
}
