package csaf

import (
	"context"
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime"
	"net/http"
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

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	if err := options.fetch(args); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (opts options) fetch(ids []string) error {
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

			a, err := opts.fetchAdvisory(client, id)
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
// no file answers to the name that title yields.
//
// The title comes from the CVRF over the wire, which carries the advisory's
// current title -- what names the CSAF after a rename.
func (opts options) fetchAdvisory(client *utilhttp.Client, id string) (*CSAF, error) {
	// The CVRF carries the advisory's current title, which is what names its
	// CSAF.
	title, err := opts.fetchCVRFTitle(client, id)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cvrf title")
	}

	// The one empty title left is a 422: an ID the endpoint will not route, which
	// the nine FG-IR-0yy-nnn advisories are. They are real advisories with no
	// title to be had here, so nothing can name their CSAF and they are skipped
	// the way one whose name resolves to no file is.
	if title == "" {
		return nil, nil
	}

	a, err := opts.fetchByTitle(client, id, title)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch by the title %q", title)
	}

	return a, nil
}

// titleOnlyCSAF holds the advisories whose CSAF is published under the older
// name, the one built from the title alone, and under no other. Fortinet
// appends the advisory ID to the name now and has backfilled that form over the
// catalogue: of the 118 advisories that still hold a title-only file, 117 answer
// to the name with the ID in it as well, and this is the one that does not.
//
// The title-only name is keyed on nothing but the title, and 28 titles in the
// catalogue are claimed by more than one advisory: csaf_os-command-injection.json
// is a single file, and five advisories share the title that names it. Reaching
// for that name on behalf of an advisory not listed here would fetch another
// advisory's CSAF, so nothing else reaches for it.
var titleOnlyCSAF = map[string]struct{}{
	"FG-IR-21-173": {},
}

func (opts options) fetchByTitle(client *utilhttp.Client, id, title string) (*CSAF, error) {
	// A CSAF is named after its advisory's title, so a title with nothing
	// alphanumeric in it names nothing at all. No title upstream is like that,
	// so one reaching here cannot resolve and did not come from an advisory.
	s := slug(title)
	if s == "" {
		return nil, errors.Errorf("no CSAF name can be derived from the title %q", title)
	}

	name := fmt.Sprintf("csaf_%s_%s.json", s, strings.ToLower(id))
	if _, ok := titleOnlyCSAF[id]; ok {
		name = fmt.Sprintf("csaf_%s.json", s)
	}

	a, err := opts.fetchCSAF(client, fmt.Sprintf(opts.csafURL, name))
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", fmt.Sprintf(opts.csafURL, name))
	}
	if a == nil {
		return nil, nil
	}

	// The name is derived, so confirm the file that answered to it is the
	// advisory that was asked for rather than trusting the derivation.
	if a.Document.Tracking.ID != id {
		return nil, errors.Errorf("unexpected advisory ID in %s. expected: %q, actual: %q", name, id, a.Document.Tracking.ID)
	}

	return a, nil
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
			_, _ = io.Copy(io.Discard, resp.Body)
			return "", errors.Errorf("unexpected media type %q", mediaType)
		}

		var a struct {
			DocumentTitle string `xml:"DocumentTitle"`
		}
		if err := xml.NewDecoder(resp.Body).Decode(&a); err != nil {
			return "", errors.Wrap(err, "decode xml")
		}

		// An ID Fortinet has no advisory for is answered with this same CVRF
		// skeleton and an empty title rather than a 404, so an empty title is not
		// an advisory that went untitled -- it is the ID naming nothing.
		if a.DocumentTitle == "" {
			return "", errors.New("no advisory under this ID. Fortinet answers an ID it does not have with an untitled CVRF")
		}

		return a.DocumentTitle, nil
	// Fortinet answers 422 for an ID it will not route, which the nine advisories
	// numbered FG-IR-0yy-nnn are -- it does not take their three digit year. They
	// are real advisories, so this is one to skip, not a run to fail.
	case http.StatusUnprocessableEntity:
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

// slug reproduces the name Fortinet derives from an advisory's title. Titles
// reach here out of XML -- the CVRF, the RSS feed -- and Fortinet encodes them
// twice there, so one level of entities outlives the parse and has to come off
// before the name matches. FG-IR-22-355 is titled "Unpassworded remotely
// accessible Redis & MongoDB" and published as
// csaf_unpassworded-remotely-accessible-redis-mongodb_fg-ir-22-355.json, not
// the ...redis-amp-mongodb... the surviving &amp; would name.
func slug(title string) string {
	return strings.Trim(nonAlphanumeric.ReplaceAllString(strings.ToLower(html.UnescapeString(title)), "-"), "-")
}
