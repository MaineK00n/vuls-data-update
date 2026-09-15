package v2

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

const baseURL = "https://security.access.redhat.com/data/csaf/v2/vex-feed/"

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

// Fetch downloads the VEX archive from /data/csaf/v2/vex-feed/, then
// catches up with the changes.csv / deletions.csv delta files, which is
// the update model Red Hat intends for this endpoint (SECDATA-1285:
// "we did not expect people doing incremental updates based on the
// archive, but individual files").
//
// Unlike /data/csaf/v2/vex/, this endpoint publishes the archive under a
// fixed name, so the delta cut-off cannot be read off the file name. It
// is derived from the archive contents instead: the newest
// document.tracking.current_release_date among the archived documents.
// Every document in the archive was generated before the snapshot was
// taken, so that timestamp never post-dates the snapshot, and any record
// written after the snapshot is therefore strictly newer. Using the
// Last-Modified header instead would lose the records published during
// the ~7-minute window between snapshot start and upload, because that
// header reports the upload time.
//
// The cut-off only ever errs towards re-downloading a document already
// present in the archive, which is harmless: the delta pass overwrites
// it with identical content.
func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "redhat", "vex", "v2"),
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

	slog.Info("Fetch RedHat CSAF VEX v2")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	name, err := options.fetchArchiveLatest(client)
	if err != nil {
		return errors.Wrap(err, "fetch archive latest")
	}

	slog.Info("Fetch RedHat CSAF VEX v2 Archive", slog.String("name", name))
	archived, err := options.fetchArchive(client, name)
	if err != nil {
		return errors.Wrap(err, "fetch archive")
	}

	slog.Info("Fetch RedHat CSAF VEX v2 Changes", slog.Time("since", archived))
	if err := options.fetchChanges(client, archived); err != nil {
		return errors.Wrap(err, "fetch changes")
	}

	slog.Info("Fetch RedHat CSAF VEX v2 Deletions", slog.Time("since", archived))
	if err := options.fetchDeletions(client, archived); err != nil {
		return errors.Wrap(err, "fetch deletions")
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

// fetchArchive writes every document in the archive and returns the
// newest document.tracking.current_release_date it saw, which the delta
// passes use as their cut-off.
func (o options) fetchArchive(client *utilhttp.Client, name string) (time.Time, error) {
	u, err := url.JoinPath(o.baseURL, name)
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

	d, err := zstd.NewReader(resp.Body)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "new zstd reader")
	}
	defer d.Close()

	var archived time.Time
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

		rt, err := time.Parse(time.RFC3339, vex.Document.Tracking.CurrentReleaseDate)
		if err != nil {
			return time.Time{}, errors.Wrapf(err, "unexpected current_release_date format. expected: %q, actual: %q", time.RFC3339, vex.Document.Tracking.CurrentReleaseDate)
		}
		if rt.After(archived) {
			archived = rt
		}

		if err := util.Write(filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)), vex); err != nil {
			return time.Time{}, errors.Wrapf(err, "write %s", filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)))
		}
	}

	if archived.IsZero() {
		// An archive with no document at all leaves no cut-off to filter
		// on, and falling through would re-download the whole feed one
		// document at a time.
		return time.Time{}, errors.New("no document in the archive")
	}

	return archived, nil
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

		rt, err := time.Parse(time.RFC3339, record[1])
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
			// changes.csv may name a document that is no longer served,
			// typically because deletions.csv retires it in the same pass.
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

		rt, err := time.Parse(time.RFC3339, record[1])
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
