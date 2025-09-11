package csaf

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/cisagov/CSAF/archive/refs/heads/develop.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "cisa", "csaf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch CISA CSAF")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch cisa csaf")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	tempDir, err := os.MkdirTemp("", "vuls-data-update")
	if err != nil {
		return errors.Wrapf(err, "mkdir %s", tempDir)
	}
	defer os.RemoveAll(tempDir)

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

		if !strings.HasPrefix(hdr.Name, "CSAF-develop") {
			continue
		}

		ss := strings.Split(hdr.Name, string(os.PathSeparator))
		if len(ss) < 2 {
			return errors.Errorf("unexpected tar header name. expected: %q, actual: %q", "<dir>/(...)", hdr.Name)
		}
		p := filepath.Join(tempDir, filepath.Join(ss[1:]...))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0755); err != nil {
				return errors.Wrapf(err, "mkdir %s", p)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				return errors.Wrapf(err, "mkdir %s", filepath.Dir(p))
			}

			if err := func() error {
				f, err := os.Create(p)
				if err != nil {
					return errors.Wrapf(err, "create %s", p)
				}
				defer f.Close()

				if _, err := io.Copy(f, tr); err != nil {
					return errors.Wrapf(err, "copy to %s", p)
				}

				return nil
			}(); err != nil {
				return errors.Wrapf(err, "create %s", p)
			}
		}
	}

	for _, p := range []string{filepath.Join("IT", "white"), filepath.Join("OT", "white")} {
		if err := func() error {
			indexf, err := os.Open(filepath.Join(tempDir, "csaf_files", p, "index.txt"))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(tempDir, "csaf_files", p, "index.txt"))
			}
			defer indexf.Close()

			scanner := bufio.NewScanner(indexf)
			for scanner.Scan() {
				f, err := os.Open(filepath.Join(tempDir, "csaf_files", p, scanner.Text()))
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(tempDir, scanner.Text()))
				}
				defer f.Close()

				var advisory CSAF
				if err := json.NewDecoder(f).Decode(&advisory); err != nil {
					return errors.Wrap(err, "decode json")
				}

				t, err := time.Parse(time.RFC3339, advisory.Document.Tracking.InitialReleaseDate)
				if err != nil {
					return errors.Wrapf(err, "failed to parse InitialReleaseDate option. expected: %q, actual: %q", time.RFC3339, advisory.Document.Tracking.InitialReleaseDate)
				}

				if err := util.Write(filepath.Join(options.dir, p, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", advisory.Document.Tracking.ID)), advisory); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, p, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", advisory.Document.Tracking.ID)))
				}
			}
			if err := scanner.Err(); err != nil {
				return errors.Wrap(err, "scanner encounter error")
			}

			return nil
		}(); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
