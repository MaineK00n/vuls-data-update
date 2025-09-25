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

const (
	baseURL = "https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle"
)

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
	opt := &options{
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "redhat", "appstream-lifecycle"),
		retry:   3,
	}
	for _, o := range opts {
		o.apply(opt)
	}

	if err := util.RemoveAll(opt.dir); err != nil {
		return errors.Wrapf(err, "remove %s", opt.dir)
	}

	log.Print("[INFO] Fetch RHEL Application Streams Life Cycle")

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opt.retry)).Get(opt.baseURL)
	if err != nil {
		return errors.Wrapf(err, "get document. URL: %s", opt.baseURL)
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
				return errors.Errorf("empty header. major: %s, title: %s", ss[1], title)
			}
			headers = append(headers, th.Text())
		}

		if len(headers) == 0 {
			return errors.Errorf("no headers found. major: %s, title: %s", ss[1], title)
		}

		switch ss[2] {
		case "Full Life Application Streams Release Life Cycle":
			t := FullLifeApplicationStreamTable{Title: title, Major: ss[1]}
			t.ApplicationStreams, err = extractFullLifeApplicationStreams(tab, headers)
			if err != nil {
				return errors.Wrapf(err, "extract full life application streams. major: %s, title: %s", ss[1], title)
			}

			if err := util.Write(filepath.Join(opt.dir, "Full-Life-Application-Streams", fmt.Sprintf("%s.json", ss[1])), t); err != nil {
				return errors.Wrapf(err, "write table. file: %s", filepath.Join(opt.dir, "Full-Life-Application-Streams", fmt.Sprintf("%s.json", ss[1])))
			}
		case "Rolling Application Streams Release Life Cycle":
			t := RollingApplicationStreamTable{Title: title, Major: ss[1]}
			t.RollingApplicationStreams, err = extractRollingApplicationStreams(tab, headers, ss[1])
			if err != nil {
				return errors.Wrapf(err, "extract rolling application streams. major: %s, title: %s", ss[1], title)
			}

			if err := util.Write(filepath.Join(opt.dir, "Rolling-Application-Streams", fmt.Sprintf("%s.json", ss[1])), t); err != nil {
				return errors.Wrapf(err, "write table. file: %s", filepath.Join(opt.dir, "Rolling-Application-Streams", fmt.Sprintf("%s.json", ss[1])))
			}
		case "Dependent Application Streams Release Life Cycle":
			t := DependentApplicationStreamTable{Title: title, Major: ss[1]}
			t.ApplicationStreams, err = extractDependentApplicationStreams(tab, headers)
			if err != nil {
				return errors.Wrapf(err, "extract dependent application streams. major: %s, title: %s", ss[1], title)
			}

			if err := util.Write(filepath.Join(opt.dir, "Dependent-Application-Streams", fmt.Sprintf("%s.json", ss[1])), t); err != nil {
				return errors.Wrapf(err, "write table . file: %s", filepath.Join(opt.dir, "Dependent-Application-Streams", fmt.Sprintf("%s.json", ss[1])))
			}
		case "Application Streams Release Life Cycle":
			t := ApplicationStreamTable{Title: title, Major: ss[1]}
			t.ApplicationStreams, err = extractApplicationStreams(tab, headers)
			if err != nil {
				return errors.Wrapf(err, "extract application streams. major: %s, title: %s", ss[1], title)
			}

			if err := util.Write(filepath.Join(opt.dir, "Application-Streams", fmt.Sprintf("%s.json", ss[1])), t); err != nil {
				return errors.Wrapf(err, "write table. file: %s", filepath.Join(opt.dir, "Application-Streams", fmt.Sprintf("%s.json", ss[1])))
			}
		default:
			return errors.Errorf("unknown table type. major: %s, title: %s", ss[1], title)
		}

	}
	return nil
}

func extractApplicationStreams(table *goquery.Selection, headers []string) ([]ApplicationStream, error) {
	var rows []ApplicationStream
	for _, tr := range table.Find("tbody tr").EachIter() {
		cells := tr.Find("td")
		if cells.Length() != len(headers) {
			return nil, errors.Errorf("unexpected number of cells. expected: %d, actual: %d", len(headers), cells.Length())
		}

		row := ApplicationStream{}
		for i, td := range cells.EachIter() {
			switch headers[i] {
			case "Application Stream":
				row.ApplicationStream = td.Text()
			case "Release Date":
				row.ReleaseDate = td.Text()
			case "Retirement Date":
				row.RetirementDate = td.Text()
			case "Release":
				row.Release = td.Text()
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

		row := FullLifeApplicationStream{}
		for i, td := range cells.EachIter() {
			switch headers[i] {
			case "Application Stream":
				row.ApplicationStream = td.Text()
			case "Release Date":
				row.ReleaseDate = td.Text()
			case "Release":
				row.Release = td.Text()
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

		row := RollingApplicationStream{}
		for i, td := range cells.EachIter() {
			switch headers[i] {
			case "Rolling Application Stream":
				row.RollingApplicationStream = td.Text()
			case "Release Date":
				row.ReleaseDate = td.Text()
			case "Product Version":
				row.ProductVersion = td.Text()
			case "Previous Release":
				href, exists := td.Find("a").First().Attr("href")
				if !exists {
					return nil, errors.Errorf("no link found in Previous Release. td: %+v", td)
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

		row := DependentApplicationStream{}
		for i, td := range cells.EachIter() {
			if i >= len(headers) {
				return nil, errors.Errorf("index out of range. i: %d headers: %d", i, len(headers))
			}
			switch headers[i] {
			case "Application Stream":
				row.ApplicationStream = td.Text()
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
