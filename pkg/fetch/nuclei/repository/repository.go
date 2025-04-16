package repository

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz"

type options struct {
	dataURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "nuclei", "repository"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Nuclei Templates from GitHub Repository")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch nuclei data")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close() //nolint:errcheck

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() || filepath.Ext(hdr.Name) != ".yaml" {
			continue
		}

		var template Template
		if err := yaml.NewDecoder(tr).Decode(&template); err != nil {
			fmt.Println(hdr.Name)
			return errors.Wrap(err, "decode yaml")
		}

		ss := strings.Split(filepath.Dir(hdr.Name), string(os.PathSeparator))
		if len(ss) < 2 {
			return errors.Errorf("unexpected template path. expected: %q, actual: %q", "nuclei-templates-main/<category>/.../<template>.yaml", hdr.Name)
		}

		if err := util.Write(filepath.Join(options.dir, filepath.Join(ss[1:]...), fmt.Sprintf("%s.json", template.ID)), template); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, filepath.Join(ss[1:]...), fmt.Sprintf("%s.json", template.ID)))
		}

	}

	return nil
}
