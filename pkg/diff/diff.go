package diff

import (
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/diff/util"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
)

type options struct {
	dir          string
	filter       string
	diffAlg      string
	remotePrefix string
}

type Option interface {
	apply(*options)
}

type dirOption string

func (o dirOption) apply(opts *options) {
	opts.dir = string(o)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type filterOption string

func (o filterOption) apply(opts *options) {
	opts.filter = string(o)
}

func WithFilter(filter string) Option {
	return filterOption(filter)
}

type diffAlgOption string

func (o diffAlgOption) apply(opts *options) {
	opts.diffAlg = string(o)
}

func WithDiffAlg(diffAlg string) Option {
	return diffAlgOption(diffAlg)
}

type remotePrefixOption string

func (o remotePrefixOption) apply(opts *options) {
	opts.remotePrefix = string(o)
}

func WithRemotePrefix(remotePrefix string) Option {
	return remotePrefixOption(remotePrefix)
}

func Diff(datasource, rootID, old, new string, opts ...Option) (WholeDiff, error) {
	options := &options{
		remotePrefix: "https://github.com/vulsio",
		dir:          filepath.Join(util.CacheDir(), "diff"),
		filter:       "tree:0",
		diffAlg:      "default",
	}
	for _, o := range opts {
		o.apply(options)
	}

	extracted := gitRepo{
		name:    fmt.Sprintf("vuls-data-extracted-%s", datasource),
		url:     fmt.Sprintf("%s/vuls-data-extracted-%s.git", options.remotePrefix, datasource),
		dir:     filepath.Join(options.dir, fmt.Sprintf("vuls-data-extracted-%s", datasource)),
		old:     old,
		new:     new,
		remotes: make(map[string]remote),
		filter:  options.filter,
		diffAlg: options.diffAlg,
	}
	log.Printf("[INFO] Working directory for extracted: %s", extracted.dir)

	if err := extracted.prepare(); err != nil {
		return WholeDiff{}, errors.Wrap(err, "prepare extracted git repository")
	}

	oldPath, err := findPathByRootID(extracted, rootID, extracted.old)
	if err != nil {
		return WholeDiff{}, errors.Wrapf(err, "find extracted old path")
	}
	newPath, err := findPathByRootID(extracted, rootID, extracted.new)
	if err != nil {
		return WholeDiff{}, errors.Wrapf(err, "find extracted new path")
	}
	fileDiff, err := extracted.getFileDiff(oldPath, newPath)
	if err != nil {
		return WholeDiff{}, errors.Wrapf(err, "get file diff")
	}

	whole := WholeDiff{
		RootID: rootID,
		Extracted: map[string]Repository{
			extracted.name: {
				Commits: extracted.getCommitRange(),
				Files:   []FileDiff{fileDiff},
			},
		},
		Raw: make(map[string]Repository),
	}

	rs, err := newRawRepos(extracted, options)
	if err != nil {
		return WholeDiff{}, errors.Wrapf(err, "new raw repos")
	}

	for n, r := range rs {
		whole.Raw[n] = Repository{
			Commits: r.getCommitRange(),
		}
	}

	rawfiles, err := listRawfiles(extracted, oldPath, newPath)
	if err != nil {
		return WholeDiff{}, errors.Wrapf(err, "list raw files")
	}

	for _, f := range rawfiles {
		rawRepo, found := rs[f.repo]
		if !found {
			return WholeDiff{}, errors.Errorf("raw repository not found. repository: %s", f.repo)
		}

		fileDiff, err := rawRepo.getFileDiff(f.oldPath, f.newPath)
		if err != nil {
			return WholeDiff{}, errors.Wrapf(err, "get file diff")
		}

		g := whole.Raw[f.repo]
		g.Files = append(g.Files, fileDiff)
		whole.Raw[f.repo] = g
	}

	return whole, nil
}

func findPathByRootID(g gitRepo, rootID, commit string) (string, error) {
	list, err := g.listTree(commit)
	if err != nil {
		return "", errors.Wrapf(err, "list tree. commit: %s", commit)
	}

	for _, s := range list {
		if strings.Contains(s, fmt.Sprintf("/%s.json", rootID)) {
			return s, nil
		}
	}
	return "", errors.Errorf("root ID not found. root ID: %s", rootID)
}

type rawfile struct {
	repo    string
	oldPath string
	newPath string
}

// newRawRepos returns map where key is repository name.
func newRawRepos(extracted gitRepo, opts *options) (map[string]gitRepo, error) {
	newContent, err := extracted.showBlob(extracted.new, "datasource.json")
	if err != nil {
		return nil, errors.Wrapf(err, "git show. commit: %s, path: %s", extracted.new, "datasource.json")
	}

	var newDs datasourceTypes.DataSource
	if err := json.Unmarshal([]byte(newContent), &newDs); err != nil {
		return nil, errors.Wrapf(err, "json unmarshal")
	}

	oldContent, err := extracted.showBlob(extracted.old, "datasource.json")
	if err != nil {
		return nil, errors.Wrapf(err, "git show. commit: %s, path: %s", extracted.old, "datasource.json")
	}

	var oldDs datasourceTypes.DataSource
	if err := json.Unmarshal([]byte(oldContent), &oldDs); err != nil {
		return nil, errors.Wrapf(err, "json unmarshal")
	}

	rawRepos := make(map[string]gitRepo)

	for _, oldRaw := range oldDs.Raw {
		name := strings.TrimSuffix(path.Base(oldRaw.URL), ".git")
		rawRepos[name] = gitRepo{
			name:    name,
			url:     oldRaw.URL,
			dir:     filepath.Join(opts.dir, name),
			old:     oldRaw.Commit,
			remotes: make(map[string]remote),
			filter:  opts.filter,
			diffAlg: opts.diffAlg,
		}
	}

	for _, newRaw := range newDs.Raw {
		name := strings.TrimSuffix(path.Base(newRaw.URL), ".git")
		switch oldRepo, found := rawRepos[name]; found {
		case true:
			// Old data found, only overwrite "new" field
			oldRepo.new = newRaw.Commit
			rawRepos[name] = oldRepo
		case false:
			// new side only
			rawRepos[name] = gitRepo{
				name:    name,
				url:     newRaw.URL,
				dir:     filepath.Join(opts.dir, name),
				new:     newRaw.Commit,
				remotes: make(map[string]remote),
				filter:  opts.filter,
				diffAlg: opts.diffAlg,
			}
		}
	}

	for name, r := range rawRepos {
		log.Printf("[INFO] Working directory for raw: %s", r.dir)
		if err := r.prepare(); err != nil {
			return nil, errors.Wrapf(err, "prepare raw git repository %s", r.url)
		}
		rawRepos[name] = r
	}

	return rawRepos, nil
}

func listRawfiles(extracted gitRepo, oldPath, newPath string) ([]rawfile, error) {
	oldBs, err := extracted.showBlob(extracted.old, oldPath)
	if err != nil {
		return nil, errors.Wrapf(err, "git show. commit: %s, path: %s", extracted.old, oldPath)
	}
	var oldData dataTypes.Data
	if err := json.Unmarshal([]byte(oldBs), &oldData); err != nil {
		// Don't report error and just continue because older Data type does not include raw file paths.
		// If dataTypes.Data struct will change, it'll be time to consider unmarhsalling it with interface{}.
		log.Printf("[WARN] unmarshal of %s failed, probably data type is stale", oldPath)
		return nil, nil
	}

	newBs, err := extracted.showBlob(extracted.new, newPath)
	if err != nil {
		return nil, errors.Wrapf(err, "git show. commit: %s, path: %s", extracted.new, newPath)
	}
	var newData dataTypes.Data
	if err := json.Unmarshal([]byte(newBs), &newData); err != nil {
		log.Printf("[WARN] unmarshal of %s failed, probably data type is stale", newPath)
		return nil, nil
	}

	rawfiles := make(map[string]rawfile)
	for _, fullpath := range oldData.DataSource.Raws {
		repo, path, found := strings.Cut(fullpath, string(filepath.Separator))
		if !found {
			return nil, errors.Errorf("raw path does not contain repository name. path: %s", fullpath)
		}

		rawfiles[fullpath] = rawfile{
			repo:    repo,
			oldPath: path,
		}
	}
	for _, fullpath := range newData.DataSource.Raws {
		repo, path, found := strings.Cut(fullpath, string(filepath.Separator))
		if !found {
			return nil, errors.Errorf("raw path does not contain repository name. path: %s", fullpath)
		}

		f := rawfiles[fullpath]
		rawfiles[fullpath] = rawfile{
			repo:    repo,
			oldPath: f.oldPath,
			newPath: path,
		}
	}

	return slices.Collect(maps.Values(rawfiles)), nil
}
