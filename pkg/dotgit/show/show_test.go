package show_test

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/show"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestShow(t *testing.T) {
	type args struct {
		// shallow makes the repository newShallowRepository instead of
		// newRepository.
		shallow  bool
		revision string
		opts     []show.Option
	}
	tests := []struct {
		name    string
		args    args
		want    show.Commit
		wantErr string
	}{
		{
			name: "full hash, native git",
			args: args{
				revision: "c32990db8f97b8b588b4a432b934aff4fc769b50", // the signed commit
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			want: show.Commit{
				Hash:          "c32990db8f97b8b588b4a432b934aff4fc769b50",
				AuthorTime:    time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC), // the commit's 2023-11-15 07:13:20 +0900, in UTC
				CommitterTime: time.Date(2023, time.November, 14, 23, 13, 20, 0, time.UTC), // the commit's 2023-11-14 18:13:20 -0500, in UTC
			},
		},
		{
			name: "full hash, go-git",
			args: args{
				revision: "c32990db8f97b8b588b4a432b934aff4fc769b50", // the signed commit
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			want: show.Commit{
				Hash:          "c32990db8f97b8b588b4a432b934aff4fc769b50",
				AuthorTime:    time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC), // the commit's 2023-11-15 07:13:20 +0900, in UTC
				CommitterTime: time.Date(2023, time.November, 14, 23, 13, 20, 0, time.UTC), // the commit's 2023-11-14 18:13:20 -0500, in UTC
			},
		},
		{
			name: "branch, native git",
			args: args{
				revision: "main",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			want: show.Commit{
				Hash:          "c32990db8f97b8b588b4a432b934aff4fc769b50",
				AuthorTime:    time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC), // the commit's 2023-11-15 07:13:20 +0900, in UTC
				CommitterTime: time.Date(2023, time.November, 14, 23, 13, 20, 0, time.UTC), // the commit's 2023-11-14 18:13:20 -0500, in UTC
			},
		},
		{
			name: "branch, go-git",
			args: args{
				revision: "main",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			want: show.Commit{
				Hash:          "c32990db8f97b8b588b4a432b934aff4fc769b50",
				AuthorTime:    time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC), // the commit's 2023-11-15 07:13:20 +0900, in UTC
				CommitterTime: time.Date(2023, time.November, 14, 23, 13, 20, 0, time.UTC), // the commit's 2023-11-14 18:13:20 -0500, in UTC
			},
		},
		{
			// The commit, not the tag object, whose header git show would
			// print before the commit.
			name: "annotated tag, native git",
			args: args{
				revision: "v1",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			want: show.Commit{
				Hash:          "c32990db8f97b8b588b4a432b934aff4fc769b50",
				AuthorTime:    time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC), // the commit's 2023-11-15 07:13:20 +0900, in UTC
				CommitterTime: time.Date(2023, time.November, 14, 23, 13, 20, 0, time.UTC), // the commit's 2023-11-14 18:13:20 -0500, in UTC
			},
		},
		{
			name: "annotated tag, go-git",
			args: args{
				revision: "v1",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			want: show.Commit{
				Hash:          "c32990db8f97b8b588b4a432b934aff4fc769b50",
				AuthorTime:    time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC), // the commit's 2023-11-15 07:13:20 +0900, in UTC
				CommitterTime: time.Date(2023, time.November, 14, 23, 13, 20, 0, time.UTC), // the commit's 2023-11-14 18:13:20 -0500, in UTC
			},
		},
		{
			// :/<text> names the youngest commit whose message matches. git
			// reads what follows it as part of the text, so the commit is not
			// peeled by appending ^{commit}.
			name: "commit message search, native git",
			args: args{
				revision: ":/signed",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			want: show.Commit{
				Hash:          "c32990db8f97b8b588b4a432b934aff4fc769b50",
				AuthorTime:    time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC), // the commit's 2023-11-15 07:13:20 +0900, in UTC
				CommitterTime: time.Date(2023, time.November, 14, 23, 13, 20, 0, time.UTC), // the commit's 2023-11-14 18:13:20 -0500, in UTC
			},
		},
		{
			// go-git skips :/<text>, and util.ResolveRevision refuses it.
			name: "commit message search, go-git",
			args: args{
				revision: ":/signed",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			wantErr: `resolve :/signed: go-git does not support ":/signed" in ":/signed", use native git: unsupported revision`,
		},
		{
			// ^{/<text>} names the youngest commit reachable from main whose
			// message matches.
			name: "commit message search from a branch, native git",
			args: args{
				revision: "main^{/signed}",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			want: show.Commit{
				Hash:          "c32990db8f97b8b588b4a432b934aff4fc769b50",
				AuthorTime:    time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC), // the commit's 2023-11-15 07:13:20 +0900, in UTC
				CommitterTime: time.Date(2023, time.November, 14, 23, 13, 20, 0, time.UTC), // the commit's 2023-11-14 18:13:20 -0500, in UTC
			},
		},
		{
			name: "commit message search from a branch, go-git",
			args: args{
				revision: "main^{/signed}",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			want: show.Commit{
				Hash:          "c32990db8f97b8b588b4a432b934aff4fc769b50",
				AuthorTime:    time.Date(2023, time.November, 14, 22, 13, 20, 0, time.UTC), // the commit's 2023-11-15 07:13:20 +0900, in UTC
				CommitterTime: time.Date(2023, time.November, 14, 23, 13, 20, 0, time.UTC), // the commit's 2023-11-14 18:13:20 -0500, in UTC
			},
		},
		{
			name: "tree of a branch, native git",
			args: args{
				revision: "main^{tree}",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			wantErr: `"main^{tree}" does not name a commit`,
		},
		{
			// go-git skips ^{tree}, and would return main's commit.
			name: "tree of a branch, go-git",
			args: args{
				revision: "main^{tree}",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			wantErr: `resolve main^{tree}: go-git does not support "^{tree}" in "main^{tree}", use native git: unsupported revision`,
		},
		{
			// main: names the top tree of main.
			name: "path in a branch, native git",
			args: args{
				revision: "main:",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			wantErr: `"main:" does not name a commit`,
		},
		{
			// go-git skips :<path>, and would return main's commit.
			name: "path in a branch, go-git",
			args: args{
				revision: "main:",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			wantErr: `resolve main:: go-git does not support ":" in "main:", use native git: unsupported revision`,
		},
		{
			name: "missing revision, native git",
			args: args{
				revision: "missing",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			wantErr: `"missing" does not name a commit`,
		},
		{
			name: "missing revision, go-git",
			args: args{
				revision: "missing",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			wantErr: `"missing" does not name a commit`,
		},
		{
			name: "tree, native git",
			args: args{
				revision: "4b825dc642cb6eb9a060e54bf8d69288fbee4904", // the empty tree the commit points to
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			wantErr: `"4b825dc642cb6eb9a060e54bf8d69288fbee4904" does not name a commit`,
		},
		{
			name: "tree, go-git",
			args: args{
				revision: "4b825dc642cb6eb9a060e54bf8d69288fbee4904", // the empty tree the commit points to
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			wantErr: `"4b825dc642cb6eb9a060e54bf8d69288fbee4904" does not name a commit`,
		},
		{
			// rev-parse prints both ends of a range, and exits 1 only with
			// --verify.
			name: "range, native git",
			args: args{
				revision: "v1..main",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			wantErr: `"v1..main" does not name a commit`,
		},
		{
			// go-git's revision parser rejects "..".
			name: "range, go-git",
			args: args{
				revision: "v1..main",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			wantErr: "resolve v1..main",
		},
		{
			// Without --end-of-options, rev-parse reads this as its own
			// --abbrev-ref option, with a mode it does not know, and exits 128.
			name: "option-like revision, native git",
			args: args{
				revision: "--abbrev-ref=unknown",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			wantErr: `"--abbrev-ref=unknown" does not name a commit`,
		},
		{
			name: "option-like revision, go-git",
			args: args{
				revision: "--abbrev-ref=unknown",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			wantErr: `"--abbrev-ref=unknown" does not name a commit`,
		},
		{
			// main of the shallow clone.
			name: "shallow commit, native git",
			args: args{
				shallow:  true,
				revision: "72dab9e35fe49df9a92e8f12014b9f226114c9d4",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			want: show.Commit{
				Hash:          "72dab9e35fe49df9a92e8f12014b9f226114c9d4",
				AuthorTime:    time.Date(2023, time.November, 15, 22, 13, 20, 0, time.UTC),
				CommitterTime: time.Date(2023, time.November, 15, 23, 13, 20, 0, time.UTC),
			},
		},
		{
			// main of the shallow clone.
			name: "shallow commit, go-git",
			args: args{
				shallow:  true,
				revision: "72dab9e35fe49df9a92e8f12014b9f226114c9d4",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			want: show.Commit{
				Hash:          "72dab9e35fe49df9a92e8f12014b9f226114c9d4",
				AuthorTime:    time.Date(2023, time.November, 15, 22, 13, 20, 0, time.UTC),
				CommitterTime: time.Date(2023, time.November, 15, 23, 13, 20, 0, time.UTC),
			},
		},
		{
			// The clone does not have the parent of its shallow commit.
			name: "parent of the shallow commit, native git",
			args: args{
				shallow:  true,
				revision: "main~1",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			wantErr: `"main~1" does not name a commit`,
		},
		{
			// go-git reads the parent's hash from the shallow commit, and
			// fails to read the parent with ErrObjectNotFound.
			name: "parent of the shallow commit, go-git",
			args: args{
				shallow:  true,
				revision: "main~1",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			wantErr: `"main~1" does not name a commit`,
		},
		{
			// A commit pinned by its full hash before the history was
			// truncated.
			name: "parent of the shallow commit by hash, native git",
			args: args{
				shallow:  true,
				revision: "14398cbfc59d80dc0da5a1d0e6d816da30418880",
				opts:     []show.Option{show.WithUseNativeGit(true)},
			},
			wantErr: `"14398cbfc59d80dc0da5a1d0e6d816da30418880" does not name a commit`,
		},
		{
			// A commit pinned by its full hash before the history was
			// truncated.
			name: "parent of the shallow commit by hash, go-git",
			args: args{
				shallow:  true,
				revision: "14398cbfc59d80dc0da5a1d0e6d816da30418880",
				opts:     []show.Option{show.WithUseNativeGit(false)},
			},
			wantErr: `"14398cbfc59d80dc0da5a1d0e6d816da30418880" does not name a commit`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := newRepository
			if tt.args.shallow {
				repository = newShallowRepository
			}
			got, err := show.Show(repository(t), tt.args.revision, tt.args.opts...)
			switch {
			case err != nil && tt.wantErr == "":
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.wantErr != "":
				t.Errorf("expected error has not occurred. want: %q", tt.wantErr)
			case err != nil:
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("unexpected err. expected: %q, actual: %v", tt.wantErr, err)
				}
			default:
				// cmp compares times with Equal, which ignores the location.
				if diff := cmp.Diff(tt.want, got, cmp.Comparer(func(x, y time.Time) bool {
					return x.Equal(y) && x.Location() == y.Location()
				})); diff != "" {
					t.Errorf("Show(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

// newRepository makes a repository whose main is a signed commit and whose
// tag v1 is an annotated tag of it. Its config sets log.showSignature=true,
// with which git show prints the signature check of the commit before the
// output of --format.
func newRepository(t *testing.T) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "vuls-data-raw-test")
	git(t, "", "init", "--quiet", "--initial-branch=main", dir)
	git(t, "", "-C", dir, "config", "log.showSignature", "true")
	for _, o := range []struct {
		typ     string
		content string
		hash    string
	}{
		{
			// The empty tree.
			typ:     "tree",
			content: "",
			hash:    "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		},
		{
			// A commit signed with a throwaway GPG key whose private key was
			// discarded. Its author and committer record different UTC
			// offsets: 2023-11-15 07:13:20 +0900 and 2023-11-14 18:13:20
			// -0500. The line after gpgsig is a single space.
			typ: "commit",
			content: `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
author A U Thor <author@example.com> 1700000000 +0900
committer C O Mitter <committer@example.com> 1700003600 -0500
gpgsig -----BEGIN PGP SIGNATURE-----
 
 iHUEABYIAB0WIQT22NdP9H1bhlr8AK2M4oN6XBQ0sQUCavaJIAAKCRCM4oN6XBQ0
 sTGMAP4xcz798waEk+09jeXKyf6/0RhE54nTIINkdN3fXXFYAgD/XtfQdNDQseSp
 DnTbFUUEW32UqtNnWti17H8WY6Uorg4=
 =XfPt
 -----END PGP SIGNATURE-----

signed
`,
			hash: "c32990db8f97b8b588b4a432b934aff4fc769b50",
		},
		{
			// An annotated tag v1 of the commit.
			typ: "tag",
			content: `object c32990db8f97b8b588b4a432b934aff4fc769b50
type commit
tag v1
tagger T Agger <tagger@example.com> 1700007200 +0000

v1
`,
			hash: "25056faa691ea5ce742c3504f31042d055750f71",
		},
	} {
		if got := git(t, o.content, "-C", dir, "hash-object", "-t", o.typ, "-w", "--stdin"); got != o.hash {
			t.Fatalf("hash-object -t %s. expected: %s, actual: %s", o.typ, o.hash, got)
		}
	}
	git(t, "", "-C", dir, "update-ref", "refs/heads/main", "c32990db8f97b8b588b4a432b934aff4fc769b50")
	git(t, "", "-C", dir, "update-ref", "refs/tags/v1", "25056faa691ea5ce742c3504f31042d055750f71")

	return dir
}

// newShallowRepository makes a clone of depth 1 of a repository whose main is
// a commit with a parent, as vuls-data-db truncates a dotgit: main is the
// shallow commit of the clone, and the clone does not have its parent.
func newShallowRepository(t *testing.T) string {
	t.Helper()

	src := filepath.Join(t.TempDir(), "src")
	git(t, "", "init", "--quiet", "--initial-branch=main", src)
	for _, o := range []struct {
		typ     string
		content string
		hash    string
	}{
		{
			// The empty tree.
			typ:     "tree",
			content: "",
			hash:    "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		},
		{
			// The parent, authored and committed at 2023-11-14 22:13:20 UTC.
			typ: "commit",
			content: `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
author A U Thor <author@example.com> 1700000000 +0000
committer C O Mitter <committer@example.com> 1700000000 +0000

parent
`,
			hash: "14398cbfc59d80dc0da5a1d0e6d816da30418880",
		},
		{
			// main, authored at 2023-11-15 22:13:20 UTC and committed an hour
			// later.
			typ: "commit",
			content: `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
parent 14398cbfc59d80dc0da5a1d0e6d816da30418880
author A U Thor <author@example.com> 1700086400 +0000
committer C O Mitter <committer@example.com> 1700090000 +0000

child
`,
			hash: "72dab9e35fe49df9a92e8f12014b9f226114c9d4",
		},
	} {
		if got := git(t, o.content, "-C", src, "hash-object", "-t", o.typ, "-w", "--stdin"); got != o.hash {
			t.Fatalf("hash-object -t %s. expected: %s, actual: %s", o.typ, o.hash, got)
		}
	}
	git(t, "", "-C", src, "update-ref", "refs/heads/main", "72dab9e35fe49df9a92e8f12014b9f226114c9d4")

	dir := filepath.Join(t.TempDir(), "vuls-data-raw-test")
	git(t, "", "clone", "--quiet", "--bare", "--depth", "1", (&url.URL{Scheme: "file", Path: src}).String(), dir)
	if bs, err := os.ReadFile(filepath.Join(dir, "shallow")); err != nil || string(bs) != "72dab9e35fe49df9a92e8f12014b9f226114c9d4\n" {
		t.Fatalf("shallow commits. expected: %q, actual: %q, err: %v", "72dab9e35fe49df9a92e8f12014b9f226114c9d4\n", bs, err)
	}

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
