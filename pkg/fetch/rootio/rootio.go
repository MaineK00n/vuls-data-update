package rootio

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://api.root.io/external/cve_feed"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "rootio"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Root.io")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var feed feed
	if err := json.UnmarshalRead(resp.Body, &feed); err != nil {
		return errors.Wrap(err, "decode json")
	}

	for distro, data := range feed {
		for _, d := range data {
			for _, p := range d.Packages {
				if err := util.Write(filepath.Join(options.dir, distro, d.DistroVersion, fmt.Sprintf("%s.json", p.Pkg.Name)), p); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, distro, d.DistroVersion, fmt.Sprintf("%s.json", p.Pkg.Name)))
				}
			}
		}
	}

	return nil
}
