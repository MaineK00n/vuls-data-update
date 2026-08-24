package msuc

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const msucURL = "https://www.catalog.update.microsoft.com"

type options struct {
	msucURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
}

type Option interface {
	apply(*options)
}

type msucURLOption string

func (u msucURLOption) apply(opts *options) {
	opts.msucURL = string(u)
}

func WithMSUCURL(url string) Option {
	return msucURLOption(url)
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

func Fetch(queries []string, opts ...Option) error {
	options := &options{
		msucURL:     msucURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "microsoft", "msuc"),
		retry:       3,
		concurrency: 5,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Windows Microsoft Software Update Catalog")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	uids, err := options.search(client, util.Unique(queries))
	if err != nil {
		return errors.Wrap(err, "search")
	}

	// The catalog answers some update pages with Thanks.aspx instead of the
	// page itself. The update's supersededby list is then unreadable, so the
	// walk stops there and everything behind it is missed; record the misses so
	// a truncated crawl leaves a trace in the log.
	var unavailable []string

	uidmap := make(map[string]struct{})
	for len(uids) > 0 {
		slog.Info("Search Update IDs", slog.Int("count", len(uids)))

		var us []string
		for _, uid := range uids {
			uidmap[uid] = struct{}{}
			us = append(us, fmt.Sprintf("%s/ScopedViewInline.aspx?updateid=%s", options.msucURL, uid))
		}

		uidChan := make(chan []string, len(us))
		unavailableChan := make(chan string, len(us))
		if err := client.PipelineGet(us, options.concurrency, options.wait, false, func(resp *http.Response) error {
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			switch path.Base(resp.Request.URL.Path) {
			case "ScopedViewInline.aspx":
				v, err := parseView(resp.Body, resp.Request.URL.Query().Get("updateid"))
				if err != nil {
					return errors.Wrap(err, "parse view")
				}

				if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%s.json", v.UpdateID)), v); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%s.json", v.UpdateID)))
				}

				var next []string
				for _, s := range v.Supersededby {
					next = append(next, s.UpdateID)
				}
				uidChan <- next

				return nil
			case "Thanks.aspx":
				switch resp.Request.URL.Query().Get("id") {
				case "190":
					unavailableChan <- requestUpdateID(resp.Request)
					return nil
				default:
					return errors.Errorf("unexpected Thanks.aspx id. expected: %q, actual: %q", []string{"190"}, resp.Request.URL.Query().Get("id"))
				}
			default:
				return errors.Errorf("unexpected url path. expected: %q, actual: %q", []string{"ScopedViewInline.aspx", "Thanks.aspx"}, path.Base(resp.Request.URL.Path))
			}
		}); err != nil {
			return errors.Wrap(err, "pipeline get")
		}
		close(uidChan)
		close(unavailableChan)
		unavailable = append(unavailable, drain(unavailableChan)...)

		uids = []string{}
		for us := range uidChan {
			for _, uid := range us {
				if _, ok := uidmap[uid]; ok {
					continue
				}
				uids = append(uids, uid)
			}
		}
		uids = util.Unique(uids)
	}

	// Name all of them. Whether a run meets the same updates every time, which
	// is expiry, or a different set each time, which is not, is the whole of
	// what says whether being refused a page should fail a fetch the way being
	// refused an answer to a search does -- and a sample cannot be compared
	// across runs.
	if len(unavailable) > 0 {
		slices.Sort(unavailable)
		slog.Warn("update pages were not served, so their supersedence chains were not walked",
			slog.Int("count", len(unavailable)),
			slog.String("updateids", strings.Join(unavailable, " ")))
	}
	// Count the records written rather than the updates walked: the crawl
	// either parses an update into a record or is refused it with Thanks.aspx,
	// and reporting the refused ones as fetched would be the same overstatement
	// this fetcher exists to stop making.
	slog.Info("Fetched updates", slog.Int("count", len(uidmap)-len(unavailable)))

	return nil
}

func (opts options) search(client *utilhttp.Client, queries []string) ([]string, error) {
	slog.Info("Search queries", slog.Int("count", len(queries)))

	header := make(http.Header)
	header.Add("Content-Type", "application/x-www-form-urlencoded")

	reqs := make([]*retryablehttp.Request, 0, len(queries))
	for _, query := range queries {
		req, err := utilhttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/Search.aspx", opts.msucURL), utilhttp.WithRequestHeader(header), utilhttp.WithRequestBody([]byte(url.Values{"q": []string{query}}.Encode())))
		if err != nil {
			return nil, errors.Wrap(err, "new request")
		}
		reqs = append(reqs, req)
	}

	uidChan := make(chan []string, len(reqs))
	missChan := make(chan string, len(reqs))
	silentChan := make(chan string, len(reqs))

	// A search is answered either with result rows or, when the catalog holds
	// nothing for the query, with an explicit "We did not find any results"
	// line. A seed whose update has been expired out of the catalog is answered
	// that second way, and that is a normal miss. Neither of the two means the
	// query was never really answered -- which is how throttling arrives here:
	// HTTP 200, the usual page shell, and nothing inside it.
	if err := client.PipelineDo(reqs, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "create new document from reader")
		}

		// The result container is part of the search page's shell, there
		// whether or not the search matched anything. A response without it is
		// not the search page -- the catalog serves its home page and
		// Thanks.aspx with HTTP 200 too -- and nothing in one can be read the
		// way the rest of this reads the search page. Say that, rather than
		// reporting it as a search the catalog declined to answer: one is
		// waited out, the other is a parser that needs fixing.
		container := doc.Find("div#tableContainer")
		if container.Length() == 0 {
			return errors.New("search response has no result container; this is not the page the parser expects")
		}

		// The table itself is only there when the search matched something.
		var us []string
		container.ChildrenFiltered("table").Find("tr").Each(func(_ int, s *goquery.Selection) {
			val, exists := s.Attr("id")
			if !exists || val == "headerRow" {
				return
			}
			id, _, ok := strings.Cut(val, "_")
			if !ok {
				slog.Warn("unexpected id", slog.String("id", val))
				return
			}
			us = append(us, id)
		})

		if len(us) == 0 {
			if doc.Find("#ctl00_catalogBody_noResultText").Length() > 0 {
				missChan <- requestQuery(resp.Request)
			} else {
				silentChan <- requestQuery(resp.Request)
			}
		}

		uidChan <- us

		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "pipeline do")
	}
	close(uidChan)
	close(missChan)
	close(silentChan)

	var uids []string
	for u := range uidChan {
		uids = append(uids, u...)
	}
	uids = util.Unique(uids)

	// Sorted so that one run's lists can be read against another's.
	missed, silent := drain(missChan), drain(silentChan)
	slices.Sort(missed)
	slices.Sort(silent)

	slog.Info("Search results", slog.Int("queries", len(queries)), slog.Int("no_result", len(missed)), slog.Int("unanswered", len(silent)), slog.Int("update_ids", len(uids)))

	// Failing here is what keeps the caller from publishing a silently short
	// result over the last good one. Name the queries as well as counting them:
	// whether the catalog stopped answering across the board or only for some
	// of them is what a retry is decided on, and both are bounded by the seed
	// list, so neither list runs away.
	if len(silent) > 0 {
		slog.Warn("search queries were not answered", slog.Int("count", len(silent)), slog.String("queries", strings.Join(silent, " ")))
		return nil, errors.Errorf("%d of %d search queries were answered with neither results nor a no-result message; the catalog is likely throttling", len(silent), len(queries))
	}

	// Updates get expired out of the catalog, so a query finding nothing is
	// normal on its own -- across three of the seed lists vuls-data-db fetches
	// with, 0.00, 0.10 and 0.40 of the seeds miss that way. Naming the ones
	// that missed, rather than only counting them, is what lets a seed list be
	// pruned: these are the seeds the catalog has nothing left for.
	if len(missed) > 0 {
		slog.Warn("search queries found nothing", slog.Int("count", len(missed)), slog.String("queries", strings.Join(missed, " ")))
	}

	// Finding nothing anywhere, though, is a seed list that has stopped
	// describing anything the catalog still holds, and handing back an empty
	// result would let the caller publish it over the last good one.
	if len(queries) > 0 && len(uids) == 0 {
		return nil, errors.Errorf("all %d search queries found nothing", len(queries))
	}

	return uids, nil
}

// drain collects everything a closed channel holds. Ordering is left to the
// caller: the crawl fills one of these per round and only the whole set is
// worth ordering, at the end.
func drain(ch <-chan string) []string {
	var vs []string
	for v := range ch {
		vs = append(vs, v)
	}
	return vs
}

// requestQuery reads back the search term a request was built with. It travels
// in the body rather than the URL, and the body a client hands to a response is
// spent, so take it from GetBody, which http.NewRequest leaves behind for a
// buffered body and retryablehttp reuses to rewind between attempts.
func requestQuery(req *http.Request) string {
	if req == nil || req.GetBody == nil {
		return ""
	}

	rc, err := req.GetBody()
	if err != nil {
		return ""
	}
	defer rc.Close()

	bs, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}

	vs, err := url.ParseQuery(string(bs))
	if err != nil {
		return ""
	}

	return vs.Get("q")
}

// requestUpdateID recovers the update a crawl request set out for. The catalog
// answers some of them with a redirect, and by then the response carries the
// redirected request rather than the original, so walk back up the chain the
// client records until a URL still names the update.
func requestUpdateID(req *http.Request) string {
	for req != nil {
		if v := req.URL.Query().Get("updateid"); v != "" {
			return v
		}
		if req.Response == nil {
			return ""
		}
		req = req.Response.Request
	}
	return ""
}

func parseView(rd io.Reader, updateID string) (*Update, error) {
	if updateID == "" {
		return nil, errors.New("updateID is empty")
	}

	doc, err := goquery.NewDocumentFromReader(rd)
	if err != nil {
		return nil, errors.Wrap(err, "create new document from reader")
	}

	// Every field below is read out of an element the update page is built
	// from, and none of these reads can tell an element that is not there from
	// one holding an empty string. A page the catalog has rebuilt, or one that
	// is not an update page at all -- it answers its home page and Thanks.aspx
	// with HTTP 200 as well -- would parse into an Update of empty fields and
	// be written out as a good record. Anchor on the title, which every update
	// page carries, so a page this cannot read fails instead of being stored.
	title := doc.Find("span#ScopedViewHandler_titleText")
	if title.Length() == 0 {
		return nil, errors.New("update page has no title element; this is not the page the parser expects")
	}

	u := Update{UpdateID: updateID}

	r := strings.NewReplacer(" ", "", "\n", "")
	var found bool

	u.Title = title.Text()
	u.LastModified = doc.Find("span#ScopedViewHandler_date").Text()
	u.Description = doc.Find("span#ScopedViewHandler_desc").Text()
	_, u.Architecture, found = strings.Cut(r.Replace(doc.Find("div#archDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#archDiv format", slog.String("expected", "...:<arch>"), slog.String("actual", r.Replace(doc.Find("div#archDiv").Text())))
	}
	_, u.Classification, found = strings.Cut(r.Replace(doc.Find("div#classificationDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#classificationDiv format", slog.String("expected", "...:<classification>"), slog.String("actual", r.Replace(doc.Find("div#classificationDiv").Text())))
	}
	_, u.SupportedProducts, found = strings.Cut(r.Replace(doc.Find("div#productsDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#productsDiv format", slog.String("expected", "...:<products>"), slog.String("actual", r.Replace(doc.Find("div#productsDiv").Text())))
	}
	_, u.SupportedLanguages, found = strings.Cut(r.Replace(doc.Find("div#languagesDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#languagesDiv format", slog.String("expected", "...:<languages>"), slog.String("actual", r.Replace(doc.Find("div#languagesDiv").Text())))
	}
	_, u.SecurityBulliten, found = strings.Cut(r.Replace(doc.Find("div#securityBullitenDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#securityBullitenDiv format", slog.String("expected", "...:<securityBulliten>"), slog.String("actual", r.Replace(doc.Find("div#securityBullitenDiv").Text())))
	}
	u.MSRCSeverity = doc.Find("span#ScopedViewHandler_msrcSeverity").Text()
	_, u.KBArticle, found = strings.Cut(r.Replace(doc.Find("div#kbDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#kbDiv format", slog.String("expected", "...:<kb>"), slog.String("actual", r.Replace(doc.Find("div#kbDiv").Text())))
	}
	_, u.MoreInfo, found = strings.Cut(r.Replace(doc.Find("div#moreInfoDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#moreInfoDiv format", slog.String("expected", "...:<moreInfo>"), slog.String("actual", r.Replace(doc.Find("div#moreInfoDiv").Text())))
	}
	_, u.SupportURL, found = strings.Cut(r.Replace(doc.Find("div#suportUrlDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#suportUrlDiv format", slog.String("expected", "...:<supportURL>"), slog.String("actual", r.Replace(doc.Find("div#suportUrlDiv").Text())))
	}

	doc.Find("div#supersededbyInfo > div > a").Each(func(_ int, s *goquery.Selection) {
		val, exists := s.Attr("href")
		if !exists {
			return
		}
		if !strings.HasPrefix(val, "ScopedViewInline.aspx?updateid=") {
			slog.Warn("unexpected href", slog.String("href", val))
			return
		}
		u.Supersededby = append(u.Supersededby, Supersededby{
			Title:    s.Text(),
			UpdateID: strings.TrimPrefix(val, "ScopedViewInline.aspx?updateid="),
		})
	})
	doc.Find("div#supersedesInfo > div").Each(func(_ int, s *goquery.Selection) {
		u.Supersedes = append(u.Supersedes, strings.TrimSpace(s.Text()))
	})

	u.RebootBehavior = doc.Find("span#ScopedViewHandler_rebootBehavior").Text()
	u.UserInput = doc.Find("span#ScopedViewHandler_userInput").Text()
	u.InstallationImpact = doc.Find("span#ScopedViewHandler_installationImpact").Text()
	u.Connectivity = doc.Find("span#ScopedViewHandler_connectivity").Text()
	_, u.UninstallNotes, found = strings.Cut(r.Replace(doc.Find("div#uninstallNotesDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#uninstallNotesDiv format", slog.String("expected", "...:<uninstallNotes>"), slog.String("actual", r.Replace(doc.Find("div#uninstallNotesDiv").Text())))
	}
	_, u.UninstallSteps, found = strings.Cut(r.Replace(doc.Find("div#uninstallStepsDiv").Text()), ":")
	if !found {
		slog.Warn("unexpected div#uninstallStepsDiv format", slog.String("expected", "...:<uninstallSteps>"), slog.String("actual", r.Replace(doc.Find("div#uninstallStepsDiv").Text())))
	}

	return &u, nil
}
