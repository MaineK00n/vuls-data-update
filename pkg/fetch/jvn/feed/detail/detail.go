package detail

import (
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	jvnutil "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://jvndb.jvn.jp/ja/feed/checksum.txt"

type options struct {
	dataURL string
	dir     string
	retry   int

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

func Fetch(opts ...Option) error {
	options := &options{
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "jvn", "feed", "detail"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch JVNDB Detail")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient), utilhttp.WithClientCheckRetry(jvnutil.CheckRetry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "get checksum")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var cs []checksum
	if err := json.UnmarshalRead(resp.Body, &cs); err != nil {
		return errors.Wrap(err, "decode json")
	}

	var filtered []checksum
	for _, c := range cs {
		if strings.HasPrefix(c.Filename, "jvndb_detail_") {
			filtered = append(filtered, c)
		}
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientHTTPClient(options.httpClient))
	// A single JPCERT-AT alert is referenced by many advisories, so cache the
	// fetched title per URL to avoid refetching.
	certTitles := make(map[string]string)

	for _, c := range filtered {
		slog.Info("Fetch JVNDB Detail Feed", slog.String("feed", c.Filename))
		vs, err := func() ([]Vulinfo, error) {
			resp, err := client.Get(c.URL)
			if err != nil {
				return nil, errors.Wrap(err, "fetch jvndb detail")
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var feed feed
			if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
				return nil, errors.Wrap(err, "decode xml")
			}

			for _, v := range feed.Vulinfo {
				for i, item := range v.VulinfoData.Affected.AffectedItem {
					var vs []string
					for _, v := range item.VersionNumber {
						if v == "" {
							continue
						}
						vs = append(vs, v)
					}
					v.VulinfoData.Affected.AffectedItem[i].VersionNumber = vs
				}
			}

			return feed.Vulinfo, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

		bar := progressbar.Default(int64(len(vs)))
		for _, a := range vs {
			for i, ref := range a.VulinfoData.Related.RelatedItem {
				// Only JPCERT-AT alert pages ("/at/") carry a fetchable title; other
				// cited JPCERT reference types (weekly reports, press releases) are
				// skipped by IsAlertURL. Match on the URL rather than VulinfoID/Name,
				// which are inconsistent in the feed. Trim once so the cache key,
				// fetch target, and error context all use the same canonical URL.
				u := strings.TrimSpace(ref.URL)
				if !jvnutil.IsAlertURL(u) {
					continue
				}
				title, ok := certTitles[u]
				if !ok {
					t, err := jvnutil.FetchTitle(client, u)
					if err != nil {
						return errors.Wrapf(err, "fetch JPCERT-AT title %s", u)
					}
					title = t
					certTitles[u] = title
				}
				a.VulinfoData.Related.RelatedItem[i].FetchedTitle = title
			}

			splitted, err := util.Split(a.VulinfoID, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "JVNDB-yyyy-\\d{6}", a.VulinfoID)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "JVNDB-yyyy-\\d{6}", a.VulinfoID)
			}

			if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", a.VulinfoID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", a.VulinfoID)))
			}

			_ = bar.Add(1)
		}
		_ = bar.Close()
	}

	return nil
}
