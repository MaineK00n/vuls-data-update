package v2

import (
	"archive/tar"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://security.access.redhat.com/data/csaf/v2/vex-feed/"

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

// Fetch downloads the daily-regenerated VEX archive from
// /data/csaf/v2/vex-feed/ and writes each contained CVE document under
// the configured output directory. The companion changes.csv /
// deletions.csv delta files are intentionally not consumed: Red Hat
// confirmed (2026-05) that the archive is regenerated once a day, which
// makes the archive itself a fresh-enough snapshot for the daily fetch
// cadence and avoids the ~7-minute backwards-discrepancy window between
// archive build start and upload.
func Fetch(opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "redhat", "vex", "v2"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch RedHat CSAF VEX v2")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	name, err := options.fetchArchiveLatest(client)
	if err != nil {
		return errors.Wrap(err, "fetch archive latest")
	}

	slog.Info("Fetch RedHat CSAF VEX v2 Archive", slog.String("name", name))
	if err := options.fetchArchive(client, name); err != nil {
		return errors.Wrap(err, "fetch archive")
	}

	return nil
}

func (o options) fetchArchiveLatest(client *utilhttp.Client) (string, error) {
	u, err := url.JoinPath(o.baseURL, "archive_latest.txt")
	if err != nil {
		return "", errors.Wrap(err, "url join")
	}

	resp, err := client.Get(u)
	if err != nil {
		return "", errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "read response body")
	}

	name := strings.TrimSpace(string(bs))
	if !strings.HasSuffix(name, ".tar.zst") {
		return "", errors.Errorf("unexpected archive_latest.txt content. expected: %q, actual: %q", "<name>.tar.zst", name)
	}
	return name, nil
}

func (o options) fetchArchive(client *utilhttp.Client, name string) error {
	u, err := url.JoinPath(o.baseURL, name)
	if err != nil {
		return errors.Wrap(err, "url join")
	}

	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := zstd.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "new zstd reader")
	}
	defer d.Close()

	tr := tar.NewReader(d)
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

		var vex VEX
		if err := json.UnmarshalRead(tr, &vex); err != nil {
			return errors.Wrap(err, "decode json")
		}

		splitted, err := util.Split(vex.Document.Tracking.ID, "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
		}

		if err := util.Write(filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)), vex); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)))
		}
	}

	return nil
}
