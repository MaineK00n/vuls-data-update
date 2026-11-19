package util

import (
	"strings"
	"unicode"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"
)

// ErrUnsupportedRevision is the cause of the error ResolveRevision returns
// for a revision that go-git does not resolve as git does.
var ErrUnsupportedRevision = errors.New("unsupported revision")

// ResolveRevision returns the commit that revision names in r, through
// go-git's (*git.Repository).ResolveRevision, which peels an annotated tag to
// its commit. A revision with a part that go-git would not resolve as git
// does is refused first, with an error that names the part and wraps
// ErrUnsupportedRevision, so that the caller can turn to native git.
//
// go-git applies a name (a ref, a hash, or "@" for HEAD) and, after it,
// ~<n>, ^<n> and ^{/<text>}. Its parser reads other parts too, and skips
// them, returning the commit of the rest. Those are refused:
//   - :<path>, :/<text> and :<n>:<path>;
//   - @{<n>}, @{-<n>}, @{upstream}, @{push} and @{<date>};
//   - ^{tree}, ^{blob}, ^{tag} and ^{object}. ^{commit} and ^{}, which peel
//     to a commit as go-git does anyway, are kept, but ^{} only at the end,
//     as go-git drops what follows it.
//
// So are the forms its parser reads otherwise than git:
//   - ^{/<text>} whose text ends with the word commit, tree, blob, tag or
//     object, which go-git reads as ^{<type>}; whose text starts with "/", or
//     after "!-" is empty or starts with "/" or "!", where go-git drops what
//     git reads as text; and whose text holds "^{", which git reads as the
//     start of a part. ^{/}, a search with no text, names the commit itself in
//     both, and is kept at the end, as is ^{};
//   - ^{!-<text>} and ^{!!<text>}, which go-git reads as ^{/!-<text>} and
//     ^{/!!<text>}, and git refuses;
//   - ~<n> and ^<n> with a digit outside 0-9, such as ~٣, which go-git reads
//     as ~0 and ^0;
//   - a NUL, which go-git drops or stops reading at.
//
// Outside ^{/<text>}, ":", "@{" and "^{" can only be revision syntax, as git
// does not allow them in a ref name.
func ResolveRevision(r *git.Repository, revision string) (*plumbing.Hash, error) {
	if part := unsupportedPart(revision); part != "" {
		return nil, errors.Wrapf(ErrUnsupportedRevision, "go-git does not support %q in %q, use native git", part, revision)
	}
	// go-git's error goes back as it is, such as plumbing.ErrReferenceNotFound
	// for a name it cannot resolve: the caller wraps it with the revision.
	return r.ResolveRevision(plumbing.Revision(revision))
}

// unsupportedPart returns the first part of revision that go-git does not
// resolve as git does, or "" if there is none. It splits revision as go-git's
// parser does: a name runs to the first ":", "@", "~" or "^"; ":" takes the
// rest of the revision; "@{" and "^{" run to the first "}"; "~" and "^" take
// the run of digits after them. For a ^{ or @{ without a "}", and for ^{x},
// which go-git refuses itself, it returns "" and leaves the error to go-git.
func unsupportedPart(revision string) string {
	if i := strings.IndexByte(revision, 0); i >= 0 {
		return revision[i : i+1]
	}

	for i := 0; i < len(revision); {
		rest := revision[i:]
		switch {
		case rest[0] == ':':
			return rest
		case strings.HasPrefix(rest, "@{"):
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				return ""
			}
			return rest[:end+1]
		case strings.HasPrefix(rest, "^{"):
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				return ""
			}
			switch body := rest[2:end]; {
			case body == "", body == "/":
				// go-git reads the token after the "}" as part of the braces,
				// and drops it.
				if end+1 < len(rest) {
					return rest
				}
			case body == "commit":
			case body == "tree", body == "blob", body == "tag", body == "object":
				return rest[:end+1]
			case strings.HasPrefix(body, "/"):
				if misreadSearch(body[1:]) {
					return rest[:end+1]
				}
			case strings.HasPrefix(body, "!-"), strings.HasPrefix(body, "!!"):
				return rest[:end+1]
			default:
				return ""
			}
			i += end + 1
		case rest[0] == '~', rest[0] == '^':
			// go-git's scanner takes any Unicode digit into the number, which
			// strconv.Atoi then fails to read, and go-git takes the number as
			// 0.
			n := len(rest) - 1 - len(strings.TrimLeftFunc(rest[1:], unicode.IsNumber))
			if strings.ContainsFunc(rest[1:1+n], func(r rune) bool { return r < '0' || r > '9' }) {
				return rest[:1+n]
			}
			i += 1 + n
		default:
			i++
		}
	}
	return ""
}

// misreadSearch reports whether go-git reads ^{/<text>} otherwise than git.
// go-git reads a run of letters as one word, and takes ^{/<text>} for
// ^{<type>} when the word before the "}" names an object type. Until it has
// taken some of the text, it skips any "/" and reads any "!-" as negation,
// while git reads one "!-" or "!!" and the rest as text. git reads the last
// "^{" of a revision as the start of a part, so a text that holds one is not
// a search there.
func misreadSearch(text string) bool {
	switch {
	case strings.HasPrefix(text, "/"):
		return true
	case strings.HasPrefix(text, "!-"):
		if rest := text[len("!-"):]; rest == "" || rest[0] == '/' || rest[0] == '!' {
			return true
		}
	}
	if strings.Contains(text, "^{") {
		return true
	}
	switch text[len(strings.TrimRightFunc(text, unicode.IsLetter)):] {
	case "commit", "tree", "blob", "tag", "object":
		return true
	default:
		return false
	}
}
