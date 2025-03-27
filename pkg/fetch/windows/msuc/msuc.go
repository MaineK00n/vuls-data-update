package msuc

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

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
	wait        int
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

type waitOption int

func (w waitOption) apply(opts *options) {
	opts.wait = int(w)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

func Fetch(queries []string, opts ...Option) error {
	options := &options{
		msucURL:     msucURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "windows", "msuc"),
		retry:       3,
		concurrency: 5,
		wait:        1,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Windows Microsoft Software Update Catalog")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	uids, err := options.search(client, util.Unique(queries))
	if err != nil {
		return errors.Wrap(err, "search")
	}

	uidmap := make(map[string]struct{})
	for {
		if len(uids) == 0 {
			break
		}

		log.Printf("[INFO] Search %d Update IDs", len(uids))

		var us []string
		for _, uid := range uids {
			uidmap[uid] = struct{}{}
			us = append(us, fmt.Sprintf("%s/ScopedViewInline.aspx?updateid=%s", options.msucURL, uid))
		}

		uidChan := make(chan []string, len(us))
		if err := client.PipelineGet(us, options.concurrency, options.wait, func(resp *http.Response) error {
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return errors.Errorf("error response with status code %d", resp.StatusCode)
			}

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
		}); err != nil {
			return errors.Wrap(err, "pipeline get")
		}
		close(uidChan)

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

	return nil
}

func (opts options) search(client *utilhttp.Client, queries []string) ([]string, error) {
	log.Printf("[INFO] Search %d queries", len(queries))

	header := make(http.Header)
	header.Add("Content-Type", "application/x-www-form-urlencoded")
	header.Add("Content-Length", "0")

	values := make(url.Values)

	reqs := make([]*retryablehttp.Request, 0, len(queries))
	for _, query := range queries {
		values.Set("q", query)
		req, err := utilhttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/Search.aspx", opts.msucURL), utilhttp.WithRequestHeader(header), utilhttp.WithRequestBody([]byte(values.Encode())))
		if err != nil {
			return nil, errors.Wrap(err, "new request")
		}
		reqs = append(reqs, req)
	}

	uidChan := make(chan []string, len(reqs))
	if err := client.PipelineDo(reqs, opts.concurrency, opts.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "create new document from reader")
		}

		var us []string
		doc.Find("div#tableContainer > table").Find("tr").Each(func(_ int, s *goquery.Selection) {
			val, exists := s.Attr("id")
			if !exists || val == "headerRow" {
				return
			}
			id, _, ok := strings.Cut(val, "_")
			if !ok {
				log.Printf(`[WARN] unexpected id. id="%s"`, val)
				return
			}
			us = append(us, id)
		})

		uidChan <- us

		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "pipeline do")
	}
	close(uidChan)

	var uids []string
	for u := range uidChan {
		uids = append(uids, u...)
	}

	return util.Unique(uids), nil
}

func parseView(rd io.Reader, updateID string) (*Update, error) {
	doc, err := goquery.NewDocumentFromReader(rd)
	if err != nil {
		return nil, errors.Wrap(err, "create new document from reader")
	}

	u := Update{UpdateID: updateID}

	if doc.Find("body").HasClass("mainBody thanks") {
		return &u, nil
	}

	r := strings.NewReplacer(" ", "", "\n", "")
	var found bool

	u.Title = doc.Find("span#ScopedViewHandler_titleText").Text()
	u.LastModified = doc.Find("span#ScopedViewHandler_date").Text()
	u.Description = doc.Find("span#ScopedViewHandler_desc").Text()
	_, u.Architecture, found = strings.Cut(r.Replace(doc.Find("div#archDiv").Text()), ":")
	if !found {
		log.Printf(`[WARN] unexpected div#archDiv format. expected: "...:<arch>", actual: "%s"`, r.Replace(doc.Find("div#archDiv").Text()))
	}
	_, u.Classification, found = strings.Cut(r.Replace(doc.Find("div#classificationDiv").Text()), ":")
	if !found {
		log.Printf(`[WARN] unexpected div#classificationDiv format. expected: "...:<classification>", actual: "%s"`, r.Replace(doc.Find("div#classificationDiv").Text()))
	}
	_, u.SupportedProducts, found = strings.Cut(r.Replace(doc.Find("div#productsDiv").Text()), ":")
	if !found {
		log.Printf(`[WARN] unexpected div#productsDiv format. expected: "...:<products>", actual: "%s"`, r.Replace(doc.Find("div#products").Text()))
	}
	_, u.SupportedLanguages, found = strings.Cut(r.Replace(doc.Find("div#languagesDiv").Text()), ":")
	if !found {
		log.Printf(`[WARN] unexpected div#languagesDiv format. expected: "...:<languages>", actual: "%s"`, r.Replace(doc.Find("div#languagesDiv").Text()))
	}
	_, u.SecurityBulliten, found = strings.Cut(r.Replace(doc.Find("div#securityBullitenDiv").Text()), ":")
	if !found {
		log.Printf(`[WARN] unexpected div#securityBullitenDiv format. expected: "...:<securityBulliten>", actual: "%s"`, r.Replace(doc.Find("div#securityBullitenDiv").Text()))
	}
	u.MSRCSeverity = doc.Find("span#ScopedViewHandler_msrcSeverity").Text()
	_, u.KBArticle, found = strings.Cut(r.Replace(doc.Find("div#kbDiv").Text()), ":")
	if !found {
		log.Printf(`[WARN] unexpected div#kbDiv format. expected: "...:<kb>", actual: "%s"`, r.Replace(doc.Find("div#kbDiv").Text()))
	}
	_, u.MoreInfo, found = strings.Cut(r.Replace(doc.Find("div#moreInfoDiv").Text()), ":")
	if !found {
		log.Printf(`[WARN] unexpected div#moreInfoDiv format. expected: "...:<moreInfo>", actual: "%s"`, r.Replace(doc.Find("div#moreInfoDiv").Text()))
	}
	_, u.SupportURL, found = strings.Cut(r.Replace(doc.Find("div#suportUrlDiv").Text()), ":")
	if !found {
		log.Printf(`[WARN] unexpected div#suportUrlDiv format. expected: "...:<suportUrl>", actual: "%s"`, r.Replace(doc.Find("div#suportUrlDiv").Text()))
	}

	doc.Find("div#supersededbyInfo > div > a").Each(func(_ int, s *goquery.Selection) {
		val, exists := s.Attr("href")
		if !exists {
			return
		}
		if !strings.HasPrefix(val, "ScopedViewInline.aspx?updateid=") {
			log.Printf(`[WARN] unexpected href. href="%s"`, val)
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
		log.Printf(`[WARN] unexpected div#uninstallNotesDiv format. expected: "...:<uninstallNotes>", actual: "%s"`, r.Replace(doc.Find("div#uninstallNotesDiv").Text()))
	}
	_, u.UninstallSteps, found = strings.Cut(r.Replace(doc.Find("div#uninstallStepsDiv").Text()), ":")
	if !found {
		log.Printf(`[WARN] unexpected div#uninstallStepsDiv format. expected: "...:<uninstallSteps>", actual: "%s"`, r.Replace(doc.Find("div#uninstallStepsDiv").Text()))
	}

	return &u, nil
}
