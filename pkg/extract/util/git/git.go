package git

import (
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/pkg/errors"

	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	"github.com/MaineK00n/vuls-data-update/pkg/version"
)

func IsGitRepository(path string) bool {
	_, err := git.PlainOpen(path)
	return err == nil
}

func GetOrigin(path string) (string, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return "", errors.Wrap(err, "open as git repository")
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return "", errors.Wrap(err, "get origin")
	}
	return remote.Config().URLs[0], nil
}

// GetDataSourceRepository describes the repository an extractor reads from
// path by its HEAD commit: the origin, the commit, its author date, and the
// builds the commit names in its trailers.
func GetDataSourceRepository(path string) (*repositoryTypes.Repository, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, errors.Wrap(err, "open as git repository")
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return nil, errors.Wrap(err, "get origin")
	}
	ref, err := repo.Head()
	if err != nil {
		return nil, errors.Wrap(err, "get HEAD")
	}

	c, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, errors.Wrap(err, "get HEAD commit")
	}

	return &repositoryTypes.Repository{
		URL:    remote.Config().URLs[0],
		Commit: ref.Hash().String(),
		Date:   &c.Author.When,
		Builds: builds(c.Message),
	}, nil
}

// GetExtractedRepository describes the repository an extractor writes into
// path: the build of vuls-data-update writing it, which every run knows, and
// the origin, when path is a git repository that has one. A run into a plain
// directory, as a test or a local extraction is, has no origin to name.
func GetExtractedRepository(path string) *repositoryTypes.Repository {
	r := repositoryTypes.Repository{Builds: []string{version.String()}}
	if u, err := GetOrigin(path); err == nil {
		r.URL = u
	}
	return &r
}

// buildTrailer keys the build of vuls-data-update in the message of a commit
// vuls-data-db makes. Its commit action (.github/actions/commit) names the
// program that wrote the commit by the last element of its module path,
// title-cased, and the build by its version:
//
//	Vuls-Data-Update: v0.0.0-20261126020019-9f06544f77cb
const buildTrailer = "Vuls-Data-Update"

// gitSpace is the whitespace git trims and skips. Its isspace() is ASCII and
// leaves out \v and \f, so to git a line of them, or of U+00A0, is not blank.
const gitSpace = " \t\n\r"

// builds reads the builds of vuls-data-update a commit message names, as
// "vuls-data-update <version>", in the order it names them. Like git, it reads
// trailers from the last paragraph after the subject, the first paragraph
// after any blank lines the message opens with, and only when every line of it
// is a trailer or the continuation of one; a message without trailers, as
// every commit before vuls-data-db named its builds is, names none. Where a
// hand-written message parts it from git, it reads less than git, never more:
// nothing from a paragraph only partly of trailers, as git reads one with a
// Signed-off-by among other lines, or from one with a comment line, and not a
// value that starts on a continuation line.
func builds(message string) []string {
	lines := strings.Split(message, "\n")
	blank := func(l string) bool { return strings.Trim(l, gitSpace) == "" }

	first := 0
	for first < len(lines) && blank(lines[first]) {
		first++
	}
	end := len(lines)
	for end > first && blank(lines[end-1]) {
		end--
	}
	start := end
	for start > first && !blank(lines[start-1]) {
		start--
	}
	if start == first {
		return nil
	}

	var (
		bs   []string
		last = -1
	)
	for i, l := range lines[start:end] {
		if strings.TrimLeft(l, gitSpace) != l {
			if i == 0 {
				return nil
			}
			if last >= 0 {
				bs[last] = fmt.Sprintf("%s %s", bs[last], strings.Trim(l, gitSpace))
			}
			continue
		}

		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return nil
		}
		// git reads "<token>://..." as a URL, not a trailer, unless
		// whitespace parts the token from the colon.
		if isTrailerToken(k) && strings.HasPrefix(v, "//") {
			return nil
		}
		k = strings.TrimRight(k, " \t")
		if !isTrailerToken(k) {
			return nil
		}
		last = -1
		if strings.EqualFold(k, buildTrailer) {
			if v = strings.Trim(v, gitSpace); v != "" {
				bs = append(bs, fmt.Sprintf("vuls-data-update %s", v))
				last = len(bs) - 1
			}
		}
	}
	return bs
}

// isTrailerToken reports whether s can key a trailer: git takes letters,
// digits and hyphens, so "GitHub Actions" is not one.
func isTrailerToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}
