package glsa

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const defaultRepoURL = "https://gitlab.com/gitlab-org/advisories-community/-/archive/main/advisories-community-main.tar.gz?path=nuget"

type options struct {
	repoURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type repoURLOption string

func (u repoURLOption) apply(opts *options) {
	opts.repoURL = string(u)
}

func WithRepoURL(repoURL string) Option {
	return repoURLOption(repoURL)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type retryOption int

func (r retryOption) apply(opts *options) {
	opts.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

func Fetch(opts ...Option) error {
	options := &options{
		repoURL: defaultRepoURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "nuget", "glsa"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Nuget GLSA")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.repoURL)
	if err != nil {
		return errors.Wrap(err, "fetch repository")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if filepath.Ext(hdr.Name) != ".yml" {
			continue
		}

		var adv GLSA
		if err := yaml.NewDecoder(tr).Decode(&adv); err != nil {
			return errors.Wrap(err, "decode yaml")
		}

		name, ok := strings.CutPrefix(adv.PackageSlug, "nuget/")
		if !ok {
			return errors.Errorf("unexpected package_slug format. expected: %q, actual: %q", "nuget/<package name>", adv.PackageSlug)
		}

		if err := util.Write(filepath.Join(options.dir, name, fmt.Sprintf("%s.json", strings.TrimSuffix(filepath.Base(hdr.Name), ".yml"))), adv); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, name, filepath.Base(hdr.Name)))
		}
	}

	return nil
}
