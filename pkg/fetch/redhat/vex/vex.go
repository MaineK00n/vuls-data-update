package vex

import (
	"archive/tar"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
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

const baseURL = "https://security.access.redhat.com/data/csaf/v2/vex/"

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        int
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

func (r concurrencyOption) apply(opts *options) {
	opts.concurrency = int(r)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption int

func (r waitOption) apply(opts *options) {
	opts.wait = int(r)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "redhat", "vex"),
		retry:       3,
		concurrency: 10,
		wait:        1,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch RedHat CSAF VEX")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	at, err := options.fetchArchiveDate(client)
	if err != nil {
		return errors.Wrap(err, "fetch archive date")
	}

	log.Printf("[INFO] Fetch RedHat CSAF VEX %s Archive", at.Format("2006-01-02"))
	if err := options.fetchArchive(client, at); err != nil {
		return errors.Wrap(err, "fetch archive")
	}

	log.Println("[INFO] Fetch RedHat CSAF VEX Changes")
	if err := options.fetchChanges(client, at); err != nil {
		return errors.Wrap(err, "fetch changes")
	}

	log.Println("[INFO] Fetch RedHat CSAF VEX Deletions")
	if err := options.fetchDeletions(client, at); err != nil {
		return errors.Wrap(err, "fetch deletions")
	}

	return nil
}

func (o options) fetchArchiveDate(client *utilhttp.Client) (time.Time, error) {
	u, err := url.JoinPath(o.baseURL, "archive_latest.txt")
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

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "read response body")
	}

	s := string(bs)
	if !strings.HasPrefix(s, "csaf_vex_") || !strings.HasSuffix(s, ".tar.zst") {
		return time.Time{}, errors.Errorf("unexpected archive file name. expected: %q, actual: %q", "csaf_vex_yyyy-mm-dd.tar.zst", s)
	}

	at, err := time.Parse("2006-01-02", strings.TrimPrefix(strings.TrimSuffix(s, ".tar.zst"), "csaf_vex_"))
	if err != nil {
		return time.Time{}, errors.Wrapf(err, "time parse. unexpected archive time format. expected: %q. actual: %q", "2006-01-02", strings.TrimPrefix(strings.TrimSuffix(s, ".tar.zst"), "csaf_vex_"))
	}

	return at, nil
}

func (o options) fetchArchive(client *utilhttp.Client, archived time.Time) error {
	u, err := url.JoinPath(o.baseURL, fmt.Sprintf("csaf_vex_%s.tar.zst", archived.Format("2006-01-02")))
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
		if err := json.NewDecoder(tr).Decode(&vex); err != nil {
			return errors.Wrap(err, "decode json")
		}

		splitted, err := util.Split(vex.Document.Tracking.ID, "-", "-")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
			return nil
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
			return nil
		}

		if err := util.Write(filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)), vex); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(o.dir, splitted[1], fmt.Sprintf("%s.json", vex.Document.Tracking.ID)))
		}
	}

	return nil
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

	if err := client.PipelineGet(urls, o.concurrency, o.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var vex VEX
			if err := json.NewDecoder(resp.Body).Decode(&vex); err != nil {
				return errors.Wrap(err, "decode json")
			}

			splitted, err := util.Split(vex.Document.Tracking.ID, "-", "-")
			if err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
				return nil
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", vex.Document.Tracking.ID)
				return nil
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
