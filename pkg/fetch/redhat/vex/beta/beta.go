package beta

import (
	"archive/tar"
	"encoding/csv"
	"encoding/json/v2"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	baseURL     = "https://security.access.redhat.com/data/csaf/v2/vex-feed/"
	archiveName = "vex-archive.tar.zst"
)

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption time.Duration

func (w waitOption) apply(opts *options) {
	opts.wait = time.Duration(w)
}

func WithWait(wait time.Duration) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "redhat", "vex", "beta"),
		retry:       3,
		concurrency: 10,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch RedHat CSAF VEX-Beta")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	if err := options.checkArchiveLatest(client); err != nil {
		return errors.Wrap(err, "check archive latest")
	}

	slog.Info("Fetch RedHat CSAF VEX-Beta Archive")
	at, err := options.fetchArchive(client)
	if err != nil {
		return errors.Wrap(err, "fetch archive")
	}
	slog.Info("Fetched RedHat CSAF VEX-Beta Archive", slog.String("modified", at.Format(time.RFC3339)))

	slog.Info("Fetch RedHat CSAF VEX-Beta Changes")
	if err := options.fetchChanges(client, at); err != nil {
		return errors.Wrap(err, "fetch changes")
	}

	slog.Info("Fetch RedHat CSAF VEX-Beta Deletions")
	if err := options.fetchDeletions(client, at); err != nil {
		return errors.Wrap(err, "fetch deletions")
	}

	return nil
}

func (o options) checkArchiveLatest(client *utilhttp.Client) error {
	u, err := url.JoinPath(o.baseURL, "archive_latest.txt")
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

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read response body")
	}

	if got := strings.TrimSpace(string(bs)); got != archiveName {
		return errors.Errorf("unexpected archive_latest.txt content. expected: %q, actual: %q", archiveName, got)
	}

	return nil
}

func (o options) fetchArchive(client *utilhttp.Client) (time.Time, error) {
	u, err := url.JoinPath(o.baseURL, archiveName)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "url join")
	}

	resp, err := client.Get(u)
	if err != nil {
		return time.Time{}, errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return time.Time{}, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	at, err := time.Parse(time.RFC1123, resp.Header.Get("Last-Modified"))
	if err != nil {
		return time.Time{}, errors.Wrapf(err, "parse Last-Modified. expected: RFC1123, actual: %q", resp.Header.Get("Last-Modified"))
	}

	d, err := zstd.NewReader(resp.Body)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "new zstd reader")
	}
	defer d.Close()

	tr := tar.NewReader(d)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return time.Time{}, errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		var vex VEX
		if err := json.UnmarshalRead(tr, &vex); err != nil {
			return time.Time{}, errors.Wrap(err, "decode json")
		}

		splitted, err := util.Split(vex.Document.Tracking.ID, "-", "-")
		if err != nil {
			return time.Time{}, errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return time.Time{}, errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
		}

		if err := util.Write(filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)), vex); err != nil {
			return time.Time{}, errors.Wrapf(err, "write %s", filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)))
		}
	}

	return at, nil
}

func (o options) fetchChanges(client *utilhttp.Client, archived time.Time) error {
	u, err := url.JoinPath(o.baseURL, "changes.csv")
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

	var urls []string
	r := csv.NewReader(resp.Body)
	for {
		record, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return errors.Wrap(err, "read csv record")
		}
		if len(record) != 2 {
			return errors.Errorf("unexpected changes.csv record format. expected: %q, actual: %q", []string{"<path>", "<datetime>"}, record)
		}

		rt, err := time.Parse("2006-01-02T15:04:05-07:00", record[1])
		if err != nil {
			return errors.Wrap(err, "parse time")
		}

		if rt.After(archived) {
			u, err := url.JoinPath(o.baseURL, record[0])
			if err != nil {
				return errors.Wrap(err, "url join")
			}
			urls = append(urls, u)
		}
	}

	if err := client.PipelineGet(urls, o.concurrency, o.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var vex VEX
			if err := json.UnmarshalRead(resp.Body, &vex); err != nil {
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

			return nil
		case http.StatusNotFound:
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil
		default:
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

func (o options) fetchDeletions(client *utilhttp.Client, archived time.Time) error {
	u, err := url.JoinPath(o.baseURL, "deletions.csv")
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

	r := csv.NewReader(resp.Body)
	for {
		record, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return errors.Wrap(err, "read csv record")
		}
		if len(record) != 2 {
			return errors.Errorf("unexpected deletions.csv record format. expected: %q, actual: %q", []string{"<path>", "<datetime>"}, record)
		}

		rt, err := time.Parse("2006-01-02T15:04:05-07:00", record[1])
		if err != nil {
			return errors.Wrap(err, "parse time")
		}

		if rt.After(archived) {
			// NOTE: a file that does not exist in .tar.zst may be written to deletions.csv.
			// e.g. https://github.com/MaineK00n/vuls-data-update/actions/runs/10653815586/job/29529368312#step:9:61
			d, f := filepath.Split(record[0])
			if err := os.Remove(filepath.Join(o.dir, d, fmt.Sprintf("%s.json", strings.ToUpper(strings.TrimSuffix(f, ".json"))))); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return errors.Wrapf(err, "remove %s", filepath.Join(o.dir, d, fmt.Sprintf("%s.json", strings.ToUpper(strings.TrimSuffix(f, ".json")))))
			}
		}
	}

	return nil
}
