package osv

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "ubuntu", "osv"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Ubuntu OSV")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch osv data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	xr, err := xz.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create xz reader")
	}

	tr := tar.NewReader(xr)
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

		var a OSV
		if err := json.NewDecoder(tr).Decode(&a); err != nil {
			return errors.Wrap(err, "decode json")
		}

		switch {
		case strings.HasPrefix(a.ID, "UBUNTU-CVE-"):
			splitted, err := util.Split(strings.TrimPrefix(a.ID, "UBUNTU-CVE-"), "-")
			if err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "UBUNTU-CVE-yyyy-\\d{4,}", a.ID)
			}
			if _, err := time.Parse("2006", splitted[0]); err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "UBUNTU-CVE-yyyy-\\d{4,}", a.ID)
			}

			if err := util.Write(filepath.Join(options.dir, "CVE", splitted[0], fmt.Sprintf("%s.json", a.ID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "CVE", splitted[0], fmt.Sprintf("%s.json", a.ID)))
			}
		case strings.HasPrefix(a.ID, "USN-"):
			t, err := time.Parse(time.RFC3339Nano, a.Published)
			if err != nil {
				return errors.Errorf("unexpected published format. expected: %q, actual: %q", time.RFC3339Nano, a.Published)
			}

			if err := util.Write(filepath.Join(options.dir, "USN", fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", a.ID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "USN", fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", a.ID)))
			}
		case strings.HasPrefix(a.ID, "LSN-"):
			t, err := time.Parse(time.RFC3339Nano, a.Published)
			if err != nil {
				return errors.Errorf("unexpected published format. expected: %q, actual: %q", time.RFC3339Nano, a.Published)
			}

			if err := util.Write(filepath.Join(options.dir, "LSN", fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", a.ID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "LSN", fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", a.ID)))
			}
		default:
			return errors.Errorf("unexpected ID prefix. expected: %q, actual: %q", []string{"UBUNTU-CVE-", "USN-", "LSN-"}, a.ID)
		}
	}

	return nil
}
