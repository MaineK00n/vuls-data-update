package msuc

import (
	"bytes"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const msucURL = "https://www.catalog.update.microsoft.com"

type options struct {
	msucURL string
	dir     string
	retry   int
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

func Fetch(queries []string, opts ...Option) error {
	options := &options{
		msucURL: msucURL,
		dir:     filepath.Join(util.SourceDir(), "windows", "msuc"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Windows Microsoft Software Update Catalog")
	uidmap := map[string]struct{}{}
	for _, q := range queries {
		uids, err := options.search(q)
		if err != nil {
			log.Printf("[WARN]: failed to search %s. err: %s", q, err)
			continue
		}

		qs := uids
		for {
			if len(qs) == 0 {
				break
			}

			var next []string
			for _, uid := range qs {
				if _, ok := uidmap[uid]; ok {
					continue
				}

				v, err := options.view(uid)
				if err != nil {
					log.Printf("[WARN]: failed to view %s. err: %s", uid, err)
					continue
				}

				if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%s.json.gz", v.UpdateID)), v); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%s.json.gz", v.UpdateID)))
				}

				uidmap[v.UpdateID] = struct{}{}
				for _, s := range v.Supersededby {
					if _, ok := uidmap[s.UpdateID]; !ok {
						next = append(next, s.UpdateID)
					}
				}
			}
			qs = next
		}
	}

	return nil
}

func (opts options) search(query string) ([]string, error) {
	log.Printf("[INFO] Search %s/Search.aspx?q=%s", opts.msucURL, query)

	values := url.Values{}
	values.Set("q", query)

	req, err := retryablehttp.NewRequest("POST", fmt.Sprintf("%s/Search.aspx", opts.msucURL), strings.NewReader(values.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "create new request")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", "0")

	rc := retryablehttp.NewClient()
	rc.RetryMax = opts.retry
	rc.Logger = nil

	resp, err := rc.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "send request")
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "create new document from reader")
	}

	var ids []string
	doc.Find("div#tableContainer > table").Find("tr").Each(func(_ int, s *goquery.Selection) {
		val, exists := s.Attr("id")
		if !exists || val == "headerRow" {
			return
		}
		id, _, ok := strings.Cut(val, "_")
		if !ok {
			log.Printf(`WARN: unexpected id. id="%s"`, val)
			return
		}
		ids = append(ids, id)
	})

	return ids, nil
}

func (opts options) view(updateID string) (Update, error) {
	log.Printf("INFO: GET %s/ScopedViewInline.aspx?updateid=%s", opts.msucURL, updateID)

	bs, err := util.FetchURL(fmt.Sprintf("%s/ScopedViewInline.aspx?updateid=%s", opts.msucURL, updateID), opts.retry)
	if err != nil {
		return Update{}, errors.Wrap(err, "fetch view")
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return Update{}, errors.Wrap(err, "create new document from reader")
	}

	u := Update{UpdateID: updateID}

	if doc.Find("body").HasClass("mainBody thanks") {
		return u, nil
	}

	r := strings.NewReplacer(" ", "", "\n", "")
	var found bool

	u.Title = doc.Find("span#ScopedViewHandler_titleText").Text()
	u.LastModified = doc.Find("span#ScopedViewHandler_date").Text()
	u.Description = doc.Find("span#ScopedViewHandler_desc").Text()
	_, u.Architecture, found = strings.Cut(r.Replace(doc.Find("div#archDiv").Text()), ":")
	if !found {
		errors.Errorf(`[WARN] unexpected div#archDiv format. expected: "...:<arch>", actual: "%s"`, r.Replace(doc.Find("div#archDiv").Text()))
	}
	_, u.Classification, found = strings.Cut(r.Replace(doc.Find("div#classificationDiv").Text()), ":")
	if !found {
		errors.Errorf(`[WARN] unexpected div#classificationDiv format. expected: "...:<classification>", actual: "%s"`, r.Replace(doc.Find("div#classificationDiv").Text()))
	}
	_, u.SupportedProducts, found = strings.Cut(r.Replace(doc.Find("div#productsDiv").Text()), ":")
	if !found {
		errors.Errorf(`[WARN] unexpected div#productsDiv format. expected: "...:<products>", actual: "%s"`, r.Replace(doc.Find("div#products").Text()))
	}
	_, u.SupportedLanguages, found = strings.Cut(r.Replace(doc.Find("div#languagesDiv").Text()), ":")
	if !found {
		errors.Errorf(`[WARN] unexpected div#languagesDiv format. expected: "...:<languages>", actual: "%s"`, r.Replace(doc.Find("div#languagesDiv").Text()))
	}
	_, u.SecurityBulliten, found = strings.Cut(r.Replace(doc.Find("div#securityBullitenDiv").Text()), ":")
	if !found {
		errors.Errorf(`[WARN] unexpected div#securityBullitenDiv format. expected: "...:<securityBulliten>", actual: "%s"`, r.Replace(doc.Find("div#securityBullitenDiv").Text()))
	}
	u.MSRCSeverity = doc.Find("span#ScopedViewHandler_msrcSeverity").Text()
	_, u.KBArticle, found = strings.Cut(r.Replace(doc.Find("div#kbDiv").Text()), ":")
	if !found {
		errors.Errorf(`[WARN] unexpected div#kbDiv format. expected: "...:<kb>", actual: "%s"`, r.Replace(doc.Find("div#kbDiv").Text()))
	}
	_, u.MoreInfo, found = strings.Cut(r.Replace(doc.Find("div#moreInfoDiv").Text()), ":")
	if !found {
		errors.Errorf(`[WARN] unexpected div#moreInfoDiv format. expected: "...:<moreInfo>", actual: "%s"`, r.Replace(doc.Find("div#moreInfoDiv").Text()))
	}
	_, u.SupportURL, found = strings.Cut(r.Replace(doc.Find("div#suportUrlDiv").Text()), ":")
	if !found {
		errors.Errorf(`[WARN] unexpected div#suportUrlDiv format. expected: "...:<suportUrl>", actual: "%s"`, r.Replace(doc.Find("div#suportUrlDiv").Text()))
	}

	doc.Find("div#supersededbyInfo > div > a").Each(func(_ int, s *goquery.Selection) {
		val, exists := s.Attr("href")
		if !exists {
			return
		}
		if !strings.HasPrefix(val, "ScopedViewInline.aspx?updateid=") {
			log.Printf(`WARN: unexpected href. href="%s"`, val)
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
		errors.Errorf(`[WARN] unexpected div#uninstallNotesDiv format. expected: "...:<uninstallNotes>", actual: "%s"`, r.Replace(doc.Find("div#uninstallNotesDiv").Text()))
	}
	_, u.UninstallSteps, found = strings.Cut(r.Replace(doc.Find("div#uninstallStepsDiv").Text()), ":")
	if !found {
		errors.Errorf(`[WARN] unexpected div#uninstallStepsDiv format. expected: "...:<uninstallSteps>", actual: "%s"`, r.Replace(doc.Find("div#uninstallStepsDiv").Text()))
	}

	return u, nil
}
