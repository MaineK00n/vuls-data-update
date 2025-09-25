package appstreamlifecycle

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle"

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(o *options) {
	o.baseURL = string(u)
}

func WithBaseURL(baseURL string) Option {
	return baseURLOption(baseURL)
}

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

func WithRetry(retry int) Option {
	return retryOption(retry)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "redhat", "appstream-lifecycle"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Print("[INFO] Fetch RHEL Application Streams Life Cycle")

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.baseURL)
	if err != nil {
		return errors.Wrapf(err, "get document. URL: %s", options.baseURL)
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

	for i, tab := range doc.Find("table").EachIter() {
		title, err := findHeadingForTable(tab)
		if err != nil {
			return errors.Wrapf(err, "find heading. table index: %d", i)
		}

		ss, err := util.Split(title, " ", " ")
		if err != nil {
			return errors.Wrapf(err, "unexpected title. expected: %q, actual: %q", "RHEL <major> ...", title)
		}
		if ss[0] != "RHEL" {
			return errors.Errorf("unexpected title. expected: %q, actual: %q", "RHEL <major> ...", title)
		}
		if _, err := strconv.Atoi(ss[1]); err != nil {
			return errors.Wrapf(err, "unexpected title. expected: %q, actual: %q", "RHEL <major> ...", title)
		}

		var headers []string
		for _, th := range tab.Find("thead tr").Last().Find("th").EachIter() {
			if th.Text() == "" {
				return errors.Errorf("empty header. title: %s", title)
			}
			headers = append(headers, th.Text())
		}
		if len(headers) == 0 {
			return errors.Errorf("no headers found. title: %s", title)
		}

		switch ss[2] {
		case "Application Streams Release Life Cycle":
			ass, err := extractApplicationStreams(tab, headers)
			if err != nil {
				return errors.Wrapf(err, "extract %s", title)
			}

			if err := util.Write(filepath.Join(options.dir, "Application-Streams", fmt.Sprintf("%s.json", ss[1])), ApplicationStreamTable{Title: title, Major: ss[1], ApplicationStreams: ass}); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "Application-Streams", fmt.Sprintf("%s.json", ss[1])))
			}
		case "Full Life Application Streams Release Life Cycle":
			ass, err := extractFullLifeApplicationStreams(tab, headers)
			if err != nil {
				return errors.Wrapf(err, "extract %s", title)
			}

			if err := util.Write(filepath.Join(options.dir, "Full-Life-Application-Streams", fmt.Sprintf("%s.json", ss[1])), FullLifeApplicationStreamTable{Title: title, Major: ss[1], ApplicationStreams: ass}); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "Full-Life-Application-Streams", fmt.Sprintf("%s.json", ss[1])))
			}
		case "Rolling Application Streams Release Life Cycle":
			ass, err := extractRollingApplicationStreams(tab, headers, ss[1])
			if err != nil {
				return errors.Wrapf(err, "extract %s", title)
			}

			if err := util.Write(filepath.Join(options.dir, "Rolling-Application-Streams", fmt.Sprintf("%s.json", ss[1])), RollingApplicationStreamTable{Title: title, Major: ss[1], RollingApplicationStreams: ass}); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "Rolling-Application-Streams", fmt.Sprintf("%s.json", ss[1])))
			}
		case "Dependent Application Streams Release Life Cycle":
			ass, err := extractDependentApplicationStreams(tab, headers)
			if err != nil {
				return errors.Wrapf(err, "extract %s", title)
			}

			if err := util.Write(filepath.Join(options.dir, "Dependent-Application-Streams", fmt.Sprintf("%s.json", ss[1])), DependentApplicationStreamTable{Title: title, Major: ss[1], ApplicationStreams: ass}); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "Dependent-Application-Streams", fmt.Sprintf("%s.json", ss[1])))
			}
		default:
			return errors.Errorf("unexpected table type. expected: %q, actual: %q", []string{"RHEL <major> Application Streams Release Life Cycle", "RHEL <major> Full Life Application Streams Release Life Cycle", "RHEL <major> Rolling Application Streams Release Life Cycle", "RHEL <major> Dependent Application Streams Release Life Cycle"}, title)
		}
	}
	return nil
}

func findHeadingForTable(table *goquery.Selection) (string, error) {
	cur := table
	for cur.Length() > 0 {
		for _, s := range cur.PrevAll().EachIter() {
			if goquery.NodeName(s) == "h2" {
				text := strings.TrimSpace(s.Text())
				if text == "" {
					return "", errors.Errorf("empty heading text")
				}
				return text, nil
			}
		}
		cur = cur.Parent()
	}
	return "", errors.New("no heading found")
}

func extractApplicationStreams(table *goquery.Selection, headers []string) ([]ApplicationStream, error) {
	var rows []ApplicationStream
	for _, tr := range table.Find("tbody tr").EachIter() {
		cells := tr.Find("td")
		if cells.Length() != len(headers) {
			return nil, errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), cells.Length())
		}

		var row ApplicationStream
		for i, c := range cells.EachIter() {
			switch headers[i] {
			case "Application Stream":
				row.ApplicationStream = c.Text()
			case "Release Date":
				row.ReleaseDate = c.Text()
			case "Retirement Date":
				row.RetirementDate = c.Text()
			case "Release":
				row.Release = c.Text()
			default:
				return nil, errors.Errorf("unexpected header. expected: %s, actual: %s", []string{"Application Stream", "Release Date", "Retirement Date", "Release"}, headers[i])
			}
		}
		if row.ApplicationStream == "" || row.ReleaseDate == "" || row.RetirementDate == "" || row.Release == "" {
			return nil, errors.Errorf("empty field in ApplicationStream. row: %+v", row)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func extractFullLifeApplicationStreams(table *goquery.Selection, headers []string) ([]FullLifeApplicationStream, error) {
	var rows []FullLifeApplicationStream
	for _, tr := range table.Find("tbody tr").EachIter() {
		cells := tr.Find("td")
		if cells.Length() != len(headers) {
			return nil, errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), cells.Length())
		}

		var row FullLifeApplicationStream
		for i, c := range cells.EachIter() {
			switch headers[i] {
			case "Application Stream":
				row.ApplicationStream = c.Text()
			case "Release Date":
				row.ReleaseDate = c.Text()
			case "Release":
				row.Release = c.Text()
			default:
				return nil, errors.Errorf("unexpected header. expected: %s, actual: %s", []string{"Application Stream", "Release Date", "Release"}, headers[i])
			}
		}
		if row.ApplicationStream == "" || row.ReleaseDate == "" || row.Release == "" {
			return nil, errors.Errorf("empty field in FullLifeApplicationStream. row: %+v", row)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func extractRollingApplicationStreams(table *goquery.Selection, headers []string, major string) ([]RollingApplicationStream, error) {
	var rows []RollingApplicationStream
	for _, tr := range table.Find("tbody tr").EachIter() {
		cells := tr.Find("td")
		if major == "8" && cells.Length() == 1 {
			// RHEL 8 table has a note row, ignore it
			continue
		}

		if cells.Length() != len(headers) {
			return nil, errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), cells.Length())
		}

		var row RollingApplicationStream
		for i, c := range cells.EachIter() {
			switch headers[i] {
			case "Rolling Application Stream":
				row.RollingApplicationStream = c.Text()
			case "Release Date":
				row.ReleaseDate = c.Text()
			case "Product Version":
				row.ProductVersion = c.Text()
			case "Previous Release":
				href, exists := c.Find("a").First().Attr("href")
				if !exists {
					return nil, errors.Errorf("no link found in Previous Release. td: %+v", c)
				}
				row.PreviousRelease = href
			default:
				return nil, errors.Errorf("unexpected header. expected: %s, actual: %s", []string{"Rolling Application Stream", "Release Date", "Product Version", "Previous Release"}, headers[i])
			}
		}
		if row.RollingApplicationStream == "" || row.ReleaseDate == "" || row.ProductVersion == "" || row.PreviousRelease == "" {
			return nil, errors.Errorf("empty field in RollingApplicationStream. row: %+v", row)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func extractDependentApplicationStreams(table *goquery.Selection, headers []string) ([]DependentApplicationStream, error) {
	var rows []DependentApplicationStream
	for _, tr := range table.Find("tbody tr").EachIter() {
		cells := tr.Find("td")
		if cells.Length() != len(headers) {
			return nil, errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), cells.Length())
		}

		var row DependentApplicationStream
		for i, c := range cells.EachIter() {
			switch headers[i] {
			case "Application Stream":
				row.ApplicationStream = c.Text()
			default:
				return nil, errors.Errorf("unexpected header. expected: %s, actual: %s", []string{"Application Stream"}, headers[i])
			}
		}
		if row.ApplicationStream == "" {
			return nil, errors.Errorf("empty field in DependentApplicationStream. row: %+v", row)
		}
		rows = append(rows, row)
	}
	return rows, nil
}
