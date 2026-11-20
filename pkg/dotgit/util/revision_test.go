package util_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestResolveRevision(t *testing.T) {
	tests := []struct {
		name     string
		revision string
		want     string
		// wantErr is the error in full, and wantErrIs a cause it wraps.
		wantErr   string
		wantErrIs error
	}{
		{
			name:     "branch",
			revision: "main",
			want:     "85e5a3135b2d418a1140fadce84f545add6afb79", // merge
		},
		{
			name:     "full hash",
			revision: "85e5a3135b2d418a1140fadce84f545add6afb79",
			want:     "85e5a3135b2d418a1140fadce84f545add6afb79", // merge
		},
		{
			name:     "abbreviated hash",
			revision: "85e5a31",
			want:     "85e5a3135b2d418a1140fadce84f545add6afb79", // merge
		},
		{
			// The commit, not the tag object.
			name:     "annotated tag",
			revision: "v1",
			want:     "4239258ba002b7da2276bd241620d6aeaa2f1d43", // second
		},
		{
			name:     "@ for HEAD",
			revision: "@",
			want:     "85e5a3135b2d418a1140fadce84f545add6afb79", // merge
		},
		{
			name:     "@~<n>",
			revision: "@~1",
			want:     "4239258ba002b7da2276bd241620d6aeaa2f1d43", // second
		},
		{
			name:     "~",
			revision: "main~",
			want:     "4239258ba002b7da2276bd241620d6aeaa2f1d43", // second
		},
		{
			name:     "~<n>",
			revision: "main~2",
			want:     "bba85ebf90d9b0aa733d62280111e4b379e79087", // first: fix the tree
		},
		{
			name:     "^",
			revision: "main^",
			want:     "4239258ba002b7da2276bd241620d6aeaa2f1d43", // second
		},
		{
			name:     "^<n>",
			revision: "main^2",
			want:     "1643647a4139f51144a052f0e9960ae04debb85e", // side!
		},
		{
			name:     "^0",
			revision: "main^0",
			want:     "85e5a3135b2d418a1140fadce84f545add6afb79", // merge
		},
		{
			name:     "^{/<text>}",
			revision: "main^{/side}",
			want:     "1643647a4139f51144a052f0e9960ae04debb85e", // side!
		},
		{
			// Inside ^{/<text>}, ":" is text.
			name:     "^{/<text>} holding a colon",
			revision: "main^{/first: fix}",
			want:     "bba85ebf90d9b0aa733d62280111e4b379e79087", // first: fix the tree
		},
		{
			// The text ends with ")", not with the word tree.
			name:     "^{/<text>} ending with an object type in parentheses",
			revision: "main^{/fix the (tree)}",
			want:     "bba85ebf90d9b0aa733d62280111e4b379e79087", // first: fix the tree
		},
		{
			// The youngest commit whose message does not match.
			name:     "^{/!-<text>}",
			revision: "main^{/!-merge}",
			want:     "4239258ba002b7da2276bd241620d6aeaa2f1d43", // second
		},
		{
			// !! is a literal !.
			name:     "^{/!!<text>}",
			revision: "main^{/!!}",
			want:     "1643647a4139f51144a052f0e9960ae04debb85e", // side!
		},
		{
			name:     "^{/<text>}~<n>",
			revision: "main^{/second}~1",
			want:     "bba85ebf90d9b0aa733d62280111e4b379e79087", // first: fix the tree
		},
		{
			// A search with no text names the commit itself.
			name:     "^{/} at the end",
			revision: "main^{/}",
			want:     "85e5a3135b2d418a1140fadce84f545add6afb79", // merge
		},
		{
			name:     "^{} at the end",
			revision: "v1^{}",
			want:     "4239258ba002b7da2276bd241620d6aeaa2f1d43", // second
		},
		{
			name:     "^{commit}",
			revision: "main^{commit}",
			want:     "85e5a3135b2d418a1140fadce84f545add6afb79", // merge
		},
		{
			name:     "^{commit}~<n>",
			revision: "main^{commit}~1",
			want:     "4239258ba002b7da2276bd241620d6aeaa2f1d43", // second
		},
		{
			name:      ":<path>",
			revision:  "main:dir",
			wantErr:   `go-git does not support ":dir" in "main:dir", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      ": for the root tree",
			revision:  "main:",
			wantErr:   `go-git does not support ":" in "main:", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      ":/<text>",
			revision:  ":/first",
			wantErr:   `go-git does not support ":/first" in ":/first", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      ":<n>:<path>",
			revision:  ":0:dir/file",
			wantErr:   `go-git does not support ":0:dir/file" in ":0:dir/file", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "@{<n>}",
			revision:  "main@{1}",
			wantErr:   `go-git does not support "@{1}" in "main@{1}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "@{<n>} alone",
			revision:  "@{1}",
			wantErr:   `go-git does not support "@{1}" in "@{1}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "@{-<n>}",
			revision:  "@{-1}",
			wantErr:   `go-git does not support "@{-1}" in "@{-1}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "@{upstream}",
			revision:  "main@{upstream}",
			wantErr:   `go-git does not support "@{upstream}" in "main@{upstream}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "@{u}",
			revision:  "main@{u}",
			wantErr:   `go-git does not support "@{u}" in "main@{u}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "@{push}",
			revision:  "main@{push}",
			wantErr:   `go-git does not support "@{push}" in "main@{push}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "@{<date>}",
			revision:  "main@{2000-01-01T00:00:00Z}",
			wantErr:   `go-git does not support "@{2000-01-01T00:00:00Z}" in "main@{2000-01-01T00:00:00Z}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// go-git's parser takes only an ISO 8601 date, and refuses this.
			name:      "@{<date>} not in ISO 8601",
			revision:  "main@{yesterday}",
			wantErr:   `go-git does not support "@{yesterday}" in "main@{yesterday}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "^{tree}",
			revision:  "main^{tree}",
			wantErr:   `go-git does not support "^{tree}" in "main^{tree}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "^{blob}",
			revision:  "main^{blob}",
			wantErr:   `go-git does not support "^{blob}" in "main^{blob}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "^{tag}",
			revision:  "main^{tag}",
			wantErr:   `go-git does not support "^{tag}" in "main^{tag}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// git names the tag object, not the commit.
			name:      "^{tag} of an annotated tag",
			revision:  "v1^{tag}",
			wantErr:   `go-git does not support "^{tag}" in "v1^{tag}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "^{object}",
			revision:  "main^{object}",
			wantErr:   `go-git does not support "^{object}" in "main^{object}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// go-git drops the ~, and returns main.
			name:      "^{} followed by ~",
			revision:  "main^{}~",
			wantErr:   `go-git does not support "^{}~" in "main^{}~", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// go-git drops x, and returns main~1.
			name:      "^{} followed by a name",
			revision:  "main^{}x~1",
			wantErr:   `go-git does not support "^{}x~1" in "main^{}x~1", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// go-git drops the ~, and returns main.
			name:      "^{/} followed by ~",
			revision:  "main^{/}~",
			wantErr:   `go-git does not support "^{/}~" in "main^{/}~", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// go-git reads ^{tree}, and returns main.
			name:      "^{/<text>} ending with tree",
			revision:  "main^{/fix the tree}",
			wantErr:   `go-git does not support "^{/fix the tree}" in "main^{/fix the tree}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "^{/commit}",
			revision:  "main^{/commit}",
			wantErr:   `go-git does not support "^{/commit}" in "main^{/commit}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "^{/blob}",
			revision:  "main^{/blob}",
			wantErr:   `go-git does not support "^{/blob}" in "main^{/blob}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "^{/tag}",
			revision:  "main^{/tag}",
			wantErr:   `go-git does not support "^{/tag}" in "main^{/tag}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "^{/object}",
			revision:  "main^{/object}",
			wantErr:   `go-git does not support "^{/object}" in "main^{/object}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// git searches for /first, go-git for first.
			name:      "^{/<text>} starting with /",
			revision:  "main^{//first}",
			wantErr:   `go-git does not support "^{//first}" in "main^{//first}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// git finds no commit that does not match an empty text, go-git
			// reads ^{}.
			name:      "^{/!-}",
			revision:  "main^{/!-}",
			wantErr:   `go-git does not support "^{/!-}" in "main^{/!-}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// git searches for a message without /merge, go-git without merge.
			name:      "^{/!-<text>} starting with /",
			revision:  "main^{/!-/merge}",
			wantErr:   `go-git does not support "^{/!-/merge}" in "main^{/!-/merge}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// git searches for a message without !-merge, go-git without merge.
			name:      "^{/!-<text>} starting with !",
			revision:  "main^{/!-!-merge}",
			wantErr:   `go-git does not support "^{/!-!-merge}" in "main^{/!-!-merge}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// git reads the last ^{ as the start of a part, and refuses the
			// revision. go-git searches for a message without a^{b.
			name:      "^{/<text>} holding ^{",
			revision:  "main^{/!-a^{b}",
			wantErr:   `go-git does not support "^{/!-a^{b}" in "main^{/!-a^{b}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// git refuses it, go-git reads ^{/!-first}.
			name:      "^{!-<text>}",
			revision:  "main^{!-first}",
			wantErr:   `go-git does not support "^{!-first}" in "main^{!-first}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// git refuses it, go-git reads ^{/!!}.
			name:      "^{!!<text>}",
			revision:  "main^{!!}",
			wantErr:   `go-git does not support "^{!!}" in "main^{!!}", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// U+0663 ARABIC-INDIC DIGIT THREE, which go-git reads as 0.
			name:      "~<n> with a digit outside 0-9",
			revision:  "main~٣",
			wantErr:   `go-git does not support "~٣" in "main~٣", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "~<n> with digits 0-9 and one outside",
			revision:  "main~1٣",
			wantErr:   `go-git does not support "~1٣" in "main~1٣", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "^<n> with a digit outside 0-9",
			revision:  "main^٣",
			wantErr:   `go-git does not support "^٣" in "main^٣", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			// go-git drops a NUL right after a name, and returns main~1.
			name:      "NUL",
			revision:  "main\x00~1",
			wantErr:   `go-git does not support "\x00" in "main\x00~1", use native git: unsupported revision`,
			wantErrIs: util.ErrUnsupportedRevision,
		},
		{
			name:      "missing name",
			revision:  "missing",
			wantErr:   "reference not found",
			wantErrIs: plumbing.ErrReferenceNotFound,
		},
		{
			// go-git refuses it itself.
			name:     "^{<word>}",
			revision: "main^{x}",
			wantErr:  `Revision invalid : "x" is not a valid revision suffix brace component`,
		},
		{
			// go-git refuses it itself, as git does.
			name:     "^{!<text>}",
			revision: "main^{!x}",
			wantErr:  `Revision invalid : revision suffix brace component sequences starting with "/!" others than those defined are reserved`,
		},
		{
			// go-git refuses it itself.
			name:     "^{ without }",
			revision: "main^{tree",
			wantErr:  `Revision invalid : "tree" is not a valid revision suffix brace component`,
		},
		{
			// go-git refuses it itself.
			name:     "@{ without }",
			revision: "main@{1",
			wantErr:  `Revision invalid : missing "}" in @{<data>} structure`,
		},
		{
			// go-git refuses it itself.
			name:     "range",
			revision: "v1..main",
			wantErr:  `Revision invalid : must not contains ".."`,
		},
	}
	repository := newRepository(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := git.PlainOpen(repository)
			if err != nil {
				t.Fatalf("open %s. err: %v", repository, err)
			}

			got, err := util.ResolveRevision(r, tt.revision)
			switch {
			case err != nil && tt.wantErr == "":
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.wantErr != "":
				t.Errorf("expected error has not occurred. want: %q, got: %s", tt.wantErr, got)
			case err != nil:
				if err.Error() != tt.wantErr {
					t.Errorf("unexpected err. expected: %q, actual: %q", tt.wantErr, err)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("unexpected err. expected it to wrap %q, actual: %q", tt.wantErrIs, err)
				}
			default:
				if got.String() != tt.want {
					t.Errorf("ResolveRevision(). expected: %s, actual: %s", tt.want, got)
				}
			}
		})
	}
}

// newRepository makes a repository whose main is a merge commit, and whose
// tag v1 is an annotated tag of the first parent of it:
//
//	$ git log --graph --format='%h %s%d' main
//	*   85e5a31 merge (HEAD -> main)
//	|\
//	| * 1643647 side!
//	* | 4239258 second (tag: v1)
//	|/
//	* bba85eb first: fix the tree
//
// The first parent of the merge, second, is younger than side!, so git, which
// searches the youngest commit first, and go-git, which searches the first
// parent first, find the same commits.
func newRepository(t *testing.T) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "vuls-data-raw-test")
	run(t, "", "init", "--quiet", "--initial-branch=main", dir)
	for _, o := range []struct {
		typ     string
		content string
		hash    string
	}{
		{
			// The empty tree, which each commit points to.
			typ:     "tree",
			content: "",
			hash:    "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		},
		{
			typ: "commit",
			content: `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
author A U Thor <author@example.com> 1700000000 +0000
committer C O Mitter <committer@example.com> 1700000000 +0000

first: fix the tree
`,
			hash: "bba85ebf90d9b0aa733d62280111e4b379e79087",
		},
		{
			typ: "commit",
			content: `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
parent bba85ebf90d9b0aa733d62280111e4b379e79087
author A U Thor <author@example.com> 1700001000 +0000
committer C O Mitter <committer@example.com> 1700001000 +0000

side!
`,
			hash: "1643647a4139f51144a052f0e9960ae04debb85e",
		},
		{
			typ: "commit",
			content: `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
parent bba85ebf90d9b0aa733d62280111e4b379e79087
author A U Thor <author@example.com> 1700002000 +0000
committer C O Mitter <committer@example.com> 1700002000 +0000

second
`,
			hash: "4239258ba002b7da2276bd241620d6aeaa2f1d43",
		},
		{
			typ: "commit",
			content: `tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
parent 4239258ba002b7da2276bd241620d6aeaa2f1d43
parent 1643647a4139f51144a052f0e9960ae04debb85e
author A U Thor <author@example.com> 1700003000 +0000
committer C O Mitter <committer@example.com> 1700003000 +0000

merge
`,
			hash: "85e5a3135b2d418a1140fadce84f545add6afb79",
		},
		{
			typ: "tag",
			content: `object 4239258ba002b7da2276bd241620d6aeaa2f1d43
type commit
tag v1
tagger T Agger <tagger@example.com> 1700004000 +0000

v1
`,
			hash: "39ede2c83272f3a41fc418c8d25ccb8220187277",
		},
	} {
		if got := run(t, o.content, "-C", dir, "hash-object", "-t", o.typ, "-w", "--stdin"); got != o.hash {
			t.Fatalf("hash-object -t %s. expected: %s, actual: %s", o.typ, o.hash, got)
		}
	}
	run(t, "", "-C", dir, "update-ref", "refs/heads/main", "85e5a3135b2d418a1140fadce84f545add6afb79")
	run(t, "", "-C", dir, "update-ref", "refs/tags/v1", "39ede2c83272f3a41fc418c8d25ccb8220187277")

	return dir
}

func run(t *testing.T, stdin string, args ...string) string {
	t.Helper()

	bs, err := util.GitWithStdin(strings.NewReader(stdin), args...)
	if err != nil {
		t.Fatalf("git %q. err: %v", args, err)
	}
	return strings.TrimSpace(string(bs))
}
