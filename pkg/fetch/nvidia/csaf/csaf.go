package csaf

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/NVIDIA/product-security/archive/refs/heads/main.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "nvidia", "csaf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch NVIDIA CSAF")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch nvidia csaf")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
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

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Security bulletins are laid out as <root>/<initial publication year>/<bulletin id>/<bulletin id>.json.
		// The sibling CVE-<year>-<id>.json files hold the same bulletin in the CVE Record Format and are out of scope here.
		ss := strings.Split(hdr.Name, "/")
		if len(ss) != 4 || ss[3] != fmt.Sprintf("%s.json", ss[2]) {
			continue
		}

		var advisory CSAF
		if err := json.UnmarshalRead(tr, &advisory); err != nil {
			return errors.Wrapf(err, "decode %s", hdr.Name)
		}

		t, err := time.Parse(time.RFC3339, advisory.Document.Tracking.InitialReleaseDate)
		if err != nil {
			return errors.Wrapf(err, "unexpected initial_release_date format. expected: %q, actual: %q", time.RFC3339, advisory.Document.Tracking.InitialReleaseDate)
		}

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", advisory.Document.Tracking.ID)), advisory); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", advisory.Document.Tracking.ID)))
		}
	}

	return nil
}
