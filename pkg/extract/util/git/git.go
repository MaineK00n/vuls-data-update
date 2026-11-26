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

// builds reads the builds of vuls-data-update a commit message names, as
// "vuls-data-update <version>", in the order it names them. It reads trailers
// from the last paragraph after the subject, and only when every line of it is
// a trailer or the continuation of one, which is how git reads the messages
// vuls-data-db writes; a message without trailers, as every commit before
// vuls-data-db named its builds is, names none. It does not follow git into a
// hand-written message's corners: a paragraph only partly of trailers, comment
// lines, URL lines, or a value that starts on a continuation line.
func builds(message string) []string {
	lines := strings.Split(message, "\n")

	end := len(lines)
	for end > 0 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	start := end
	for start > 0 && strings.TrimSpace(lines[start-1]) != "" {
		start--
	}
	if start == 0 {
		return nil
	}

	var (
		bs   []string
		last = -1
	)
	for i, l := range lines[start:end] {
		if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") {
			if i == 0 {
				return nil
			}
			if last >= 0 {
				bs[last] = fmt.Sprintf("%s %s", bs[last], strings.TrimSpace(l))
			}
			continue
		}

		k, v, ok := strings.Cut(l, ":")
		k = strings.TrimRight(k, " \t")
		if !ok || !isTrailerToken(k) {
			return nil
		}
		last = -1
		if strings.EqualFold(k, buildTrailer) {
			if v = strings.TrimSpace(v); v != "" {
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
