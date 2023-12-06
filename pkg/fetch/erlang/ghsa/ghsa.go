package ghsa

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/github/advisory-database/archive/refs/heads/main.tar.gz" // Erlang

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
		dir:     filepath.Join(util.CacheDir(), "erlang", "ghsa"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Erlang GHSA")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch ghsa data")
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

		if filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		var advisory GHSA
		if err := json.NewDecoder(tr).Decode(&advisory); err != nil {
			return errors.Wrap(err, "decode json")
		}

		var as []Affected
		for _, a := range advisory.Affected {
			if a.Package.Ecosystem == "Hex" {
				as = append(as, a)
			}
		}
		if len(as) == 0 {
			continue
		}
		advisory.Affected = as

		t, err := time.Parse("2006-01-02T15:04:05Z", advisory.Published)
		if err != nil {
			return errors.Wrap(err, "parse time")
		}

		if err := util.Write(filepath.Join(options.dir, t.Format("2006"), t.Format("01"), advisory.ID, fmt.Sprintf("%s.json", advisory.ID)), advisory); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, t.Format("2006"), t.Format("01"), advisory.ID, fmt.Sprintf("%s.json", advisory.ID)))
		}
	}

	return nil
}
