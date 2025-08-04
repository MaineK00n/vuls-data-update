package cvrf_cve

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://ftp.suse.com/pub/projects/security/cvrf-cve.tar.bz2"

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(opts *options) {
	opts.baseURL = string(u)
}

func WithBaseURL(url string) Option {
	return baseURLOption(url)
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
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "suse", "cvrf-cve"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch SUSE CVRF CVE")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientCheckRetry(checkRetry)).Get(options.baseURL)
	if err != nil {
		return errors.Wrap(err, "fetch suse cvrf cve")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	tr := tar.NewReader(bzip2.NewReader(resp.Body))
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

		if filepath.Ext(hdr.Name) != ".xml" {
			continue
		}

		var adv CVRF
		if err := xml.NewDecoder(tr).Decode(&adv); err != nil {
			return errors.Wrap(err, "decode xml")
		}

		splitted, err := util.Split(adv.DocumentTitle, "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", adv.DocumentTitle)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", adv.DocumentTitle)
		}

		if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", adv.DocumentTitle)), adv); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", adv.DocumentTitle)))
		}
	}

	return nil
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if shouldRetry, err := retryablehttp.ErrorPropagatedRetryPolicy(ctx, resp, err); shouldRetry {
		return shouldRetry, errors.Wrap(err, "retry policy")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, errors.Wrap(err, "read all response body")
	}

	tr := tar.NewReader(bzip2.NewReader(bytes.NewReader(body)))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() || filepath.Ext(hdr.Name) != ".xml" {
			continue
		}

		bs, err := io.ReadAll(tr)
		if err != nil {
			return false, errors.Wrap(err, "read all tar reader")
		}

		var adv CVRF
		if err := xml.Unmarshal(bs, &adv); err != nil {
			var syntaxErr *xml.SyntaxError
			if errors.As(err, &syntaxErr) {
				return true, errors.Wrapf(syntaxErr, "decode xml. file: %q, body: %q", hdr.Name, string(bs))
			}
			return false, errors.Wrap(err, "decode xml")
		}
	}

	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	return false, nil
}
