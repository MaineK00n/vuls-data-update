package osv

import (
	"archive/zip"
	"bytes"
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

const dataURL = "https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "redhat", "osv"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch RedHat OSV")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch osv data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read all response body")
	}

	r, err := zip.NewReader(bytes.NewReader(bs), int64(len(bs)))
	if err != nil {
		return errors.Wrap(err, "create zip reader")
	}

	for _, zf := range r.File {
		if zf.FileInfo().IsDir() {
			continue
		}

		a, err := func() (*OSV, error) {
			f, err := zf.Open()
			if err != nil {
				return nil, errors.Wrapf(err, "open %s", zf.Name)
			}
			defer f.Close()

			var a OSV
			if err := json.NewDecoder(f).Decode(&a); err != nil {
				return nil, errors.Wrap(err, "decode json")
			}
			return &a, nil
		}()
		if err != nil {
			return errors.Wrapf(err, "read %s", zf.Name)
		}

		splitted, err := util.Split(a.ID, "-", ":")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "(RHBA|RHEA|RHSA)-yyyy:\\d+", a.ID)
			continue
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "(RHBA|RHEA|RHSA)-yyyy:\\d+", a.ID)
			continue
		}

		if err := util.Write(filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.ID)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.ID)))
		}
	}

	return nil
}
