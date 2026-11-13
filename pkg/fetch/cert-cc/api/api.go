package api

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/filepath"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	baseURL = "https://kb.cert.org/vuls/api/"

	// startYear is the earliest year whose {year}/summary/ lists any note.
	// Every year from 1990 to 1999 answers {"count": 0, "notes": []}.
	startYear = 2000
)

var noteIDPattern = regexp.MustCompile(`^[0-9]+$`)

// errContentNotFound is returned when the API answers HTTP 200 with an
// {"error": "..."} object in place of the requested content.
var errContentNotFound = errors.New("content not found")

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration

	// httpClient is only ever set by WithHTTPClient, which lives in
	// export_test.go and is therefore absent from the production build.
	httpClient *http.Client
}

type Option interface {
	apply(*options)
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
		dir:         filepath.Join(util.CacheDir(), "fetch", "cert-cc", "api"),
		retry:       3,
		concurrency: 3,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	// errgroup gives a zero limit an unbuffered semaphore, so the first Go
	// call would block forever. Reject it before anything is removed or
	// requested, as utilhttp's PipelineDo does for its own callers.
	if options.concurrency == 0 {
		return errors.Errorf("unexpected concurrency. expected: %s, actual: %d", "a non-zero number", options.concurrency)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch CERT/CC Vulnerability Notes API")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient))

	slog.Info("Fetch CERT/CC Vulnerability Notes Summary", slog.Int("from", startYear), slog.Int("to", time.Now().Year()))
	ns, err := options.list(client)
	if err != nil {
		return errors.Wrap(err, "list notes")
	}

	slog.Info("Fetch CERT/CC Vulnerability Notes")
	if err := options.notes(client, ns); err != nil {
		return errors.Wrap(err, "fetch notes")
	}

	return nil
}

type listed struct {
	year int
	id   string
}

func (opts options) list(client *utilhttp.Client) ([]listed, error) {
	var ns []listed
	seen := make(map[string]struct{})
	for y := startYear; y <= time.Now().Year(); y++ {
		u := fmt.Sprintf("%s%d/summary/", opts.baseURL, y)

		var s summary
		if err := opts.get(context.Background(), client, u, &s); err != nil {
			return nil, errors.Wrapf(err, "fetch %s", u)
		}

		for _, n := range s.Notes {
			id, ok := strings.CutPrefix(n, "VU#")
			if !ok || !noteIDPattern.MatchString(id) {
				return nil, errors.Errorf("unexpected note id format. expected: %q, actual: %q", "VU#<digits>", n)
			}
			if _, ok := seen[id]; ok {
				slog.Warn("duplicate note listing", slog.String("id", fmt.Sprintf("VU#%s", id)), slog.Int("year", y))
				continue
			}
			seen[id] = struct{}{}
			ns = append(ns, listed{year: y, id: id})
		}
	}
	return ns, nil
}

func (opts options) notes(client *utilhttp.Client, ns []listed) error {
	nChan := make(chan listed)
	go func() {
		defer close(nChan)
		for _, n := range ns {
			nChan <- n
		}
	}()

	bar := progressbar.Default(int64(len(ns)))
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(opts.concurrency)
	for n := range nChan {
		g.Go(func() error {
			defer func() {
				_ = bar.Add(1)
			}()

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			v, err := opts.note(ctx, client, n.id)
			if err != nil {
				if errors.Is(err, errContentNotFound) {
					slog.Warn("note may have been withdrawn or made private", slog.String("id", fmt.Sprintf("VU#%s", n.id)), slog.String("err", err.Error()))
					return nil
				}
				return errors.Wrapf(err, "fetch VU#%s", n.id)
			}

			p, err := utilfilepath.Join(opts.dir, fmt.Sprintf("%d", n.year), fmt.Sprintf("%s.json", n.id))
			if err != nil {
				return errors.Wrap(err, "join")
			}

			if err := util.Write(p, v); err != nil {
				return errors.Wrapf(err, "write %s", p)
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

func (opts options) note(ctx context.Context, client *utilhttp.Client, id string) (VulnerabilityNote, error) {
	var v VulnerabilityNote
	for _, e := range []struct {
		path string
		v    any
	}{
		{path: "", v: &v.Note},
		{path: "vuls/", v: &v.Vuls},
		{path: "vendors/", v: &v.Vendors},
		{path: "vendors/vuls/", v: &v.VendorVuls},
	} {
		u := fmt.Sprintf("%s%s/%s", opts.baseURL, id, e.path)
		if err := opts.get(ctx, client, u, e.v); err != nil {
			return VulnerabilityNote{}, errors.Wrapf(err, "fetch %s", u)
		}
	}
	return v, nil
}

func (opts options) get(ctx context.Context, client *utilhttp.Client, u string, v any) error {
	// Wait after every request, including one that fails or answers with the
	// error object, but stop waiting once the group is cancelled.
	defer func() {
		select {
		case <-ctx.Done():
		case <-time.After(opts.wait):
		}
	}()

	req, err := utilhttp.NewRequest(http.MethodGet, u)
	if err != nil {
		return errors.Wrap(err, "new request")
	}

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return errors.Wrap(err, "http get")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read all response body")
	}

	// The API reports a missing or private note with HTTP 200 and an
	// {"error": "..."} object, whatever the endpoint's usual shape.
	var e errorResponse
	if err := json.Unmarshal(bs, &e); err == nil && e.Error != "" {
		return errors.Wrapf(errContentNotFound, "error response: %q", e.Error)
	}

	if err := json.Unmarshal(bs, v); err != nil {
		return errors.Wrap(err, "decode json")
	}

	return nil
}
