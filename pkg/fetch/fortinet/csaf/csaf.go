package csaf

import (
	"context"
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	csafURL = "https://filestore.fortinet.com/fortiguard/psirt/%s"
	cvrfURL = "https://www.fortiguard.com/psirt/cvrf/%s"
)

type options struct {
	csafURL     string
	cvrfURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
}

type Option interface {
	apply(*options)
}

type csafURLOption string

func (u csafURLOption) apply(opts *options) {
	opts.csafURL = string(u)
}

func WithCSAFURL(url string) Option {
	return csafURLOption(url)
}

type cvrfURLOption string

func (u cvrfURLOption) apply(opts *options) {
	opts.cvrfURL = string(u)
}

func WithCVRFURL(url string) Option {
	return cvrfURLOption(url)
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

func Fetch(args []string, opts ...Option) error {
	options := &options{
		csafURL:     csafURL,
		cvrfURL:     cvrfURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "fortinet", "csaf"),
		retry:       3,
		concurrency: 3,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	// Read the held advisories before the tree is swept: their titles name the
	// CSAF files, and the sweep is what would lose them.
	titles, err := options.storedTitles(args)
	if err != nil {
		return errors.Wrapf(err, "collect stored titles in %s", options.dir)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	if err := options.fetch(args, titles); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

// storedTitles maps each requested advisory ID that the output directory
// already holds to the title recorded in it.
func (opts options) storedTitles(ids []string) (map[string]string, error) {
	titles := make(map[string]string, len(ids))

	if _, err := os.Stat(opts.dir); err != nil {
		if os.IsNotExist(err) {
			return titles, nil
		}
		return nil, errors.Wrapf(err, "stat %s", opts.dir)
	}

	if err := filepath.WalkDir(opts.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return errors.Wrapf(err, "walk %s", path)
		}

		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var a struct {
			Document struct {
				Title    string `json:"title"`
				Tracking struct {
					ID string `json:"id"`
				} `json:"tracking"`
			} `json:"document"`
		}
		if err := json.UnmarshalRead(f, &a); err != nil {
			slog.Warn("skip a file that does not decode as CSAF", "path", path, "err", err)
			return nil
		}

		if slices.Contains(ids, a.Document.Tracking.ID) {
			titles[a.Document.Tracking.ID] = a.Document.Title
		}

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", opts.dir)
	}

	return titles, nil
}

func (opts options) fetch(ids []string, titles map[string]string) error {
	slog.Info("Fetch Fortinet CSAF")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))

	bar := progressbar.Default(int64(len(ids)))
	g, _ := errgroup.WithContext(context.TODO())
	g.SetLimit(opts.concurrency)
	for _, id := range ids {
		g.Go(func() error {
			defer func() {
				time.Sleep(opts.wait)
				_ = bar.Add(1)
			}()

			a, err := opts.fetchAdvisory(client, id, titles[id])
			if err != nil {
				return errors.Wrapf(err, "fetch %s", id)
			}
			if a == nil {
				slog.Warn("no CSAF found for the advisory. it either carries no CSAF or its CSAF has been renamed", "id", id)
				return nil
			}

			if err := opts.write(*a); err != nil {
				return errors.Wrapf(err, "write %s", id)
			}

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}
	_ = bar.Close()

	return nil
}

// fetchAdvisory resolves the advisory's CSAF from its title, returning nil when
// no file answers to any name the title yields.
//
// Fortinet names a CSAF after the title the advisory carried when the file was
// written, so a title already on disk resolves it without a request. The CVRF
// carries the current title, which is the only one available for an advisory
// not held yet and the one that answers after a rename.
func (opts options) fetchAdvisory(client *utilhttp.Client, id, storedTitle string) (*CSAF, error) {
	if storedTitle != "" {
		a, err := opts.fetchByTitle(client, id, storedTitle)
		if err != nil {
			return nil, errors.Wrapf(err, "fetch by the stored title %q", storedTitle)
		}
		if a != nil {
			return a, nil
		}
	}

	title, err := opts.fetchCVRFTitle(client, id)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cvrf title")
	}
	if title == "" || title == storedTitle {
		return nil, nil
	}

	a, err := opts.fetchByTitle(client, id, title)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch by the cvrf title %q", title)
	}
	return a, nil
}

// fetchByTitle tries the names Fortinet builds a CSAF filename from:
// csaf_<title slug>_<advisory id>.json, and csaf_<title slug>.json for the
// advisories named before the ID was appended.
func (opts options) fetchByTitle(client *utilhttp.Client, id, title string) (*CSAF, error) {
	s := slug(title)
	if s == "" {
		return nil, nil
	}

	for _, n := range []struct {
		name   string
		pinsID bool
	}{
		{name: fmt.Sprintf("csaf_%s_%s.json", s, strings.ToLower(id)), pinsID: true},
		{name: fmt.Sprintf("csaf_%s.json", s), pinsID: false},
	} {
		a, err := opts.fetchCSAF(client, fmt.Sprintf(opts.csafURL, n.name))
		if err != nil {
			return nil, errors.Wrapf(err, "fetch %s", fmt.Sprintf(opts.csafURL, n.name))
		}
		if a == nil {
			continue
		}

		// The name is derived, so confirm the file that answered to it is the
		// advisory that was asked for rather than trusting the derivation.
		if a.Document.Tracking.ID != id {
			// A name carrying the ID leaves no room for another advisory to own
			// it, so a mismatch there is upstream contradicting itself. The name
			// without it is shared ground -- titles repeat, and "OS command
			// injection" alone covers five advisories -- so a mismatch there only
			// means this advisory is not the one that holds the name.
			if n.pinsID {
				return nil, errors.Errorf("unexpected advisory ID in %s. expected: %q, actual: %q", n.name, id, a.Document.Tracking.ID)
			}

			continue
		}

		return a, nil
	}

	return nil, nil
}

func (opts options) fetchCSAF(client *utilhttp.Client, url string) (*CSAF, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", url)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var a CSAF
		if err := json.UnmarshalRead(resp.Body, &a); err != nil {
			return nil, errors.Wrap(err, "decode json")
		}

		return &a, nil
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	default:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}
}

func (opts options) fetchCVRFTitle(client *utilhttp.Client, id string) (string, error) {
	resp, err := client.Get(fmt.Sprintf(opts.cvrfURL, id))
	if err != nil {
		return "", errors.Wrapf(err, "fetch %s", fmt.Sprintf(opts.cvrfURL, id))
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return "", errors.Wrapf(err, "parse media type %q", resp.Header.Get("Content-Type"))
		}
		if !slices.Contains([]string{"application/xml", "text/xml"}, mediaType) {
			bs, _ := io.ReadAll(resp.Body)
			return "", errors.Errorf("unexpected media type %q. response body: %q", mediaType, string(bs))
		}

		var a struct {
			DocumentTitle string `xml:"DocumentTitle"`
		}
		if err := xml.NewDecoder(resp.Body).Decode(&a); err != nil {
			return "", errors.Wrap(err, "decode xml")
		}

		return a.DocumentTitle, nil
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", nil
	default:
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}
}

func (opts options) write(a CSAF) error {
	ss, err := util.Split(a.Document.Tracking.ID, "-", "-", "-")
	if err != nil {
		return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "FG-IR-yy-\\d+", a.Document.Tracking.ID)
	}
	t, err := time.Parse("06", ss[2])
	if err != nil {
		return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "FG-IR-yy-\\d+", a.Document.Tracking.ID)
	}

	if err := util.Write(filepath.Join(opts.dir, t.Format("2006"), fmt.Sprintf("%s.json", a.Document.Tracking.ID)), a); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, t.Format("2006"), fmt.Sprintf("%s.json", a.Document.Tracking.ID)))
	}

	return nil
}

var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)

func slug(title string) string {
	return strings.Trim(nonAlphanumeric.ReplaceAllString(strings.ToLower(title), "-"), "-")
}
