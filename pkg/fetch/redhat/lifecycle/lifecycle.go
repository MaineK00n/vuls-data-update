package lifecycle

import (
	"io"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	urlLifecycle = "https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle"
)

type options struct {
	url   string
	dir   string
	retry int
}

type urlOption string

func (u urlOption) apply(o *options) {
	o.url = string(u)
}

func WithURL(u string) Option {
	return urlOption(u)
}

type Option interface{ apply(*options) }

type dirOption string

func (d dirOption) apply(o *options) {
	o.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type retryOption int

func (r retryOption) apply(o *options) {
	o.retry = int(r)
}

func WithRetry(r int) Option {
	return retryOption(r)
}

type TableFile struct {
	Title                       string                       `json:"title"`
	Major                       string                       `json:"major"`
	ApplicationStreams          []ApplicationStream          `json:"application_streams,omitempty"`
	FullLifeApplicationStreams  []FullLifeApplicationStream  `json:"full_life_application_streams,omitempty"`
	RollingApplicationStreams   []RollingApplicationStream   `json:"rolling_application_streams,omitempty"`
	DependentApplicationStreams []DependentApplicationStream `json:"dependent_application_streams,omitempty"`
	Source                      string                       `json:"source"`
}

// Stream structs per table type (headers with spaces removed => snake_case JSON tags)
type ApplicationStream struct {
	ApplicationStream string `json:"application_stream,omitempty"`
	ReleaseDate       string `json:"release_date,omitempty"`
	RetirementDate    string `json:"retirement_date,omitempty"`
	Release           string `json:"release,omitempty"`
}

type FullLifeApplicationStream struct {
	ApplicationStream string `json:"application_stream,omitempty"`
	ReleaseDate       string `json:"release_date,omitempty"`
	Release           string `json:"release,omitempty"`
}

type RollingApplicationStream struct {
	RollingApplicationStream string `json:"rolling_application_stream,omitempty"`
	ReleaseDate              string `json:"release_date,omitempty"`
	ProductVersion           string `json:"product_version,omitempty"`
	PreviousRelease          string `json:"previous_release,omitempty"`
}

type DependentApplicationStream struct {
	ApplicationStream string `json:"application_stream,omitempty"`
}

// Fetch downloads the lifecycle page and writes each table as a JSON file.
func Fetch(opts ...Option) error {
	opt := &options{
		retry: 3,
		dir:   filepath.Join(util.CacheDir(), "fetch", "redhat", "lifecycle"),
		url:   urlLifecycle,
	}
	for _, o := range opts {
		o.apply(opt)
	}

	log.Printf("[INFO] Fetch RHEL Application Streams Life Cycle: %s", opt.url)
	if err := util.RemoveAll(opt.dir); err != nil {
		return errors.Wrapf(err, "remove %s", opt.dir)
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opt.retry)).Get(opt.url)
	if err != nil {
		return errors.Wrapf(err, "get document. URL: %s", opt.url)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "parse html")
	}

	// Select all tables under main content.
	tables := doc.Find("table")
	for i, t := range tables.EachIter() {
		// Find heading just before the table.
		titleText, err := findHeadingForTable(t)
		if err != nil {
			log.Printf("[WARN] skip table %d: %v", i, err)
			continue
		}
		major := extractMajor(titleText)
		headers := extractHeaders(t)
		if len(headers) == 0 {
			log.Printf("[WARN] skip table %d: no headers", i)
			continue
		}

		file := sanitizeFilename(titleText) + ".json"
		out := TableFile{Title: titleText, Major: major, Source: opt.url}

		lowerTitle := strings.ToLower(titleText)
		switch {
		case strings.Contains(lowerTitle, "application streams release life cycle") && !strings.Contains(lowerTitle, "full life") && !strings.Contains(lowerTitle, "rolling") && !strings.Contains(lowerTitle, "dependent"):
			out.ApplicationStreams = extractApplicationStreams(t, headers)
		case strings.Contains(lowerTitle, "full life application streams release life cycle"):
			out.FullLifeApplicationStreams = extractFullLifeApplicationStreams(t, headers)
		case strings.Contains(lowerTitle, "rolling application streams release life cycle"):
			out.RollingApplicationStreams = extractRollingApplicationStreams(t, headers)
		case strings.Contains(lowerTitle, "dependent application streams release life cycle"):
			out.DependentApplicationStreams = extractDependentApplicationStreams(t, headers)
		default:
			// Not a target table.
			log.Printf("[WARN] skip table %d: heading not recognized: %s", i, titleText)
			continue
		}

		if err := util.Write(filepath.Join(opt.dir, file), out); err != nil {
			return errors.Wrapf(err, "write table json. file: %s", filepath.Join(opt.dir, file))
		}
		log.Printf("[INFO] wrote %s", file)
	}
	return nil
}

var reMultiSpace = regexp.MustCompile(`\s+`)
var reMajor = regexp.MustCompile(`RHEL\s+(\d+)`)

func extractMajor(title string) string {
	m := reMajor.FindStringSubmatch(title)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	s = reMultiSpace.ReplaceAllString(s, "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "..", "-")
	return s
}

func normalizeHeader(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func extractHeaders(table *goquery.Selection) []string {
	var headers []string
	table.Find("thead tr").Last().Find("th").Each(func(_ int, th *goquery.Selection) {
		text := strings.TrimSpace(th.Text())
		if text != "" {
			headers = append(headers, text)
		}
	})
	return headers
}

func extractApplicationStreams(table *goquery.Selection, headers []string) []ApplicationStream {
	var rows []ApplicationStream
	table.Find("tbody tr").Each(func(_ int, tr *goquery.Selection) {
		cells := tr.Find("td")
		if cells.Length() == 0 {
			return
		}
		row := ApplicationStream{}
		cells.Each(func(i int, td *goquery.Selection) {
			if i >= len(headers) {
				return
			}
			key := normalizeHeader(headers[i])
			val := strings.TrimSpace(td.Text())
			switch key {
			case "ApplicationStream":
				row.ApplicationStream = val
			case "ReleaseDate":
				row.ReleaseDate = val
			case "RetirementDate":
				row.RetirementDate = val
			case "Release":
				row.Release = val
			}
		})
		if row.ApplicationStream != "" {
			rows = append(rows, row)
		}
	})
	return rows
}

func extractFullLifeApplicationStreams(table *goquery.Selection, headers []string) []FullLifeApplicationStream {
	var rows []FullLifeApplicationStream
	table.Find("tbody tr").Each(func(_ int, tr *goquery.Selection) {
		cells := tr.Find("td")
		if cells.Length() == 0 {
			return
		}
		row := FullLifeApplicationStream{}
		cells.Each(func(i int, td *goquery.Selection) {
			if i >= len(headers) {
				return
			}
			key := normalizeHeader(headers[i])
			val := strings.TrimSpace(td.Text())
			switch key {
			case "ApplicationStream":
				row.ApplicationStream = val
			case "ReleaseDate":
				row.ReleaseDate = val
			case "Release":
				row.Release = val
			}
		})
		if row.ApplicationStream != "" {
			rows = append(rows, row)
		}
	})
	return rows
}

func extractRollingApplicationStreams(table *goquery.Selection, headers []string) []RollingApplicationStream {
	var rows []RollingApplicationStream
	table.Find("tbody tr").Each(func(_ int, tr *goquery.Selection) {
		cells := tr.Find("td")
		if cells.Length() == 0 {
			return
		}
		row := RollingApplicationStream{}
		cells.Each(func(i int, td *goquery.Selection) {
			if i >= len(headers) {
				return
			}
			key := normalizeHeader(headers[i])
			val := strings.TrimSpace(td.Text())
			switch key {
			case "RollingApplicationStream":
				row.RollingApplicationStream = val
			case "ReleaseDate":
				row.ReleaseDate = val
			case "ProductVersion":
				row.ProductVersion = val
			case "PreviousRelease":
				row.PreviousRelease = val
			}
		})
		if row.RollingApplicationStream != "" {
			rows = append(rows, row)
		}
	})
	return rows
}

func extractDependentApplicationStreams(table *goquery.Selection, headers []string) []DependentApplicationStream {
	var rows []DependentApplicationStream
	table.Find("tbody tr").Each(func(_ int, tr *goquery.Selection) {
		cells := tr.Find("td")
		if cells.Length() == 0 {
			return
		}
		row := DependentApplicationStream{}
		cells.Each(func(i int, td *goquery.Selection) {
			if i >= len(headers) {
				return
			}
			key := normalizeHeader(headers[i])
			val := strings.TrimSpace(td.Text())
			if key == "ApplicationStream" {
				row.ApplicationStream = val
			}
		})
		if row.ApplicationStream != "" {
			rows = append(rows, row)
		}
	})
	return rows
}

// findHeadingForTable walks backwards from the table to locate a heading element and returns its text.
func findHeadingForTable(table *goquery.Selection) (string, error) {
	cur := table
	for cur.Length() > 0 {
		// Check previous siblings.
		for _, s := range cur.PrevAll().EachIter() {
			if isHeading(s) {
				text := strings.TrimSpace(s.Text())
				if text != "" {
					return text, nil
				}
			}
			// Also check within the sibling for heading tags.
			hs := s.Find("h1, h2, h3, h4, h5, h6")
			if hs.Length() > 0 {
				for _, h := range hs.EachIter() {
					text := strings.TrimSpace(h.Text())
					if text != "" {
						return text, nil
					}
				}
			}
		}
		cur = cur.Parent()
	}
	return "", errors.New("no heading found")
}

func isHeading(s *goquery.Selection) bool {
	if s.Length() == 0 {
		return false
	}
	n := strings.ToLower(goquery.NodeName(s))
	switch n {
	case "h1", "h2", "h3", "h4", "h5", "h6":
		return true
	default:
		return false
	}
}
