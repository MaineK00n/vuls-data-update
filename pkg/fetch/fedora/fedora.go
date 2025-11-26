package fedora

import (
	"context"
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fedora/xmlrpc"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	releaseURL  = "https://bodhi.fedoraproject.org/releases?page=%d&rows_per_page=%d"
	advisoryURL = "https://bodhi.fedoraproject.org/updates/?releases=%s&type=security&page=%d&rows_per_page=%d"
	packageURL  = "https://koji.fedoraproject.org/kojihub"
	bugzillaURL = "https://bugzilla.redhat.com/show_bug.cgi?ctype=xml&id=%s"
)

type options struct {
	dataURL     DataURL
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
	rowsPerPage int
}

type Option interface {
	apply(*options)
}

type DataURL struct {
	Release  string
	Advisory string
	Package  string
	Bugzilla string
}

type dataURLOption DataURL

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = DataURL(u)
}

func WithDataURL(url DataURL) Option {
	return dataURLOption(url)
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

type rowsPerPageOption int

func (r rowsPerPageOption) apply(opts *options) {
	opts.rowsPerPage = int(r)
}

func WithRowsPerPage(rowsPerPage int) Option {
	return rowsPerPageOption(rowsPerPage)
}

func Fetch(releases []string, opts ...Option) error {
	options := &options{
		dataURL: DataURL{
			Release:  releaseURL,
			Advisory: advisoryURL,
			Package:  packageURL,
			Bugzilla: bugzillaURL,
		},
		dir:         filepath.Join(util.CacheDir(), "fetch", "fedora"),
		retry:       20,
		concurrency: 5,
		wait:        1 * time.Second,
		rowsPerPage: 50,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	extracted, err := options.releases(client, releases)
	if err != nil {
		return errors.Wrap(err, "extract release")
	}

	for _, release := range extracted {
		log.Printf("[INFO] Fetch Fedora %s", release)
		log.Printf("[INFO] Fetch Fedora %s Advisory List", release)
		advs, err := options.advisories(client, release)
		if err != nil {
			return errors.Wrapf(err, "fetch %s security advisories", release)
		}

		log.Printf("[INFO] Finish Fedora %s Advisory", release)
		advChan := make(chan Advisory, len(advs))
		go func() {
			defer close(advChan)
			for _, adv := range advs {
				advChan <- adv
			}
		}()

		bar := progressbar.Default(int64(len(advs)))
		g, ctx := errgroup.WithContext(context.Background())
		g.SetLimit(options.concurrency)
		for adv := range advChan {
			g.Go(func() error {
				defer func() {
					_ = bar.Add(1)
				}()

				if err := options.advisory(client, &adv); err != nil {
					return errors.Wrapf(err, "finish %s %s", release, adv.Alias)
				}

				splitted, err := util.Split(strings.TrimPrefix(adv.Alias, adv.Release.IDPrefix), "-", "-")
				if err != nil {
					return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "<ID Prefix>-yyyy-.+", adv.Alias)
				}
				if _, err := time.Parse("2006", splitted[1]); err != nil {
					return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "<ID Prefix>-yyyy-.+", adv.Alias)
				}

				if err := util.Write(filepath.Join(options.dir, release, splitted[1], fmt.Sprintf("%s.json", adv.Alias)), adv); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, fmt.Sprintf("%s.json", adv.Alias)))
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					return nil
				}
			})
		}
		if err := g.Wait(); err != nil {
			return errors.Wrap(err, "err in goroutine")
		}
		_ = bar.Close()
	}

	return nil
}

func (opts options) releases(client *utilhttp.Client, releases []string) ([]string, error) {
	if !slices.Contains(releases, "__current__") && !slices.Contains(releases, "__pending__") && !slices.Contains(releases, "__archived__") {
		return releases, nil
	}

	resp, err := client.Get(fmt.Sprintf(opts.dataURL.Release, 1, 1))
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", fmt.Sprintf(opts.dataURL.Release, 1, 1))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var p releasePage
	if err := json.UnmarshalRead(resp.Body, &p); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	pages := p.Total / opts.rowsPerPage
	if p.Total%opts.rowsPerPage != 0 {
		pages++
	}

	urls := make([]string, 0, pages)
	for i := 1; i <= pages; i++ {
		urls = append(urls, fmt.Sprintf(opts.dataURL.Release, i, opts.rowsPerPage))
	}

	respChan := make(chan []release, len(urls))
	if err := client.PipelineGet(urls, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var p releasePage
		if err := json.UnmarshalRead(resp.Body, &p); err != nil {
			return errors.Wrap(err, "decode json")
		}
		respChan <- p.Releases

		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "pipeline get")
	}
	close(respChan)

	m := make(map[string][]string)
	for rs := range respChan {
		for _, r := range rs {
			m[r.State] = append(m[r.State], r.Name)
		}
	}

	var rs []string
	for _, r := range releases {
		switch r {
		case "__current__":
			rs = append(rs, m["current"]...)
		case "__pending__":
			rs = append(rs, m["pending"]...)
		case "__archived__":
			rs = append(rs, m["archived"]...)
		default:
			rs = append(rs, r)
		}
	}

	return util.Unique(rs), nil
}

func (opts options) advisories(client *utilhttp.Client, release string) ([]Advisory, error) {
	header := make(http.Header)
	header.Set("Accept", "application/json")

	req, err := utilhttp.NewRequest(http.MethodGet, fmt.Sprintf(opts.dataURL.Advisory, release, 1, 1), utilhttp.WithRequestHeader(header))
	if err != nil {
		return nil, errors.Wrap(err, "from request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", fmt.Sprintf(opts.dataURL.Advisory, release, 1))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var p advisoryPage
	if err := json.UnmarshalRead(resp.Body, &p); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	pages := p.Total / opts.rowsPerPage
	if p.Total%opts.rowsPerPage != 0 {
		pages++
	}

	reqs := make([]*retryablehttp.Request, 0, pages)
	for i := 1; i <= pages; i++ {
		req, err := utilhttp.NewRequest(http.MethodGet, fmt.Sprintf(opts.dataURL.Advisory, release, i, opts.rowsPerPage), utilhttp.WithRequestHeader(header))
		if err != nil {
			return nil, errors.Wrap(err, "from request")
		}
		reqs = append(reqs, req)
	}

	respChan := make(chan []Advisory, len(reqs))
	if err := client.PipelineDo(reqs, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var p advisoryPage
		if err := json.UnmarshalRead(resp.Body, &p); err != nil {
			return errors.Wrap(err, "decode json")
		}

		var advs []Advisory
		for _, u := range p.Updates {
			a := Advisory{
				Alias:                    u.Alias,
				Autokarma:                u.Autokarma,
				Autotime:                 u.Autotime,
				CloseBugs:                u.CloseBugs,
				Comments:                 u.Comments,
				ContentType:              u.ContentType,
				Critpath:                 u.Critpath,
				CritpathGroups:           u.CritpathGroups,
				DateApproved:             u.DateApproved,
				DateModified:             u.DateModified,
				DatePushed:               u.DatePushed,
				DateStable:               u.DateStable,
				DateSubmitted:            u.DateSubmitted,
				DateTesting:              u.DateTesting,
				DisplayName:              u.DisplayName,
				FromTag:                  u.FromTag,
				Karma:                    u.Karma,
				Locked:                   u.Locked,
				MeetsTestingRequirements: u.MeetsTestingRequirements,
				Notes:                    u.Notes,
				Pushed:                   u.Pushed,
				Release:                  u.Release,
				Request:                  u.Request,
				RequireBugs:              u.RequireBugs,
				RequireTestcases:         u.RequireTestcases,
				Requirements:             u.Requirements,
				Severity:                 u.Severity,
				StableDays:               u.StableDays,
				StableKarma:              u.StableKarma,
				Status:                   u.Status,
				Suggest:                  u.Suggest,
				TestCases:                u.TestCases,
				TestGatingStatus:         u.TestGatingStatus,
				Title:                    u.Title,
				Type:                     u.Type,
				URL:                      u.URL,
				UnstableKarma:            u.UnstableKarma,
				Updateid:                 u.Updateid,
				User:                     u.User,
				VersionHash:              u.VersionHash,
			}
			for _, b := range u.Bugs {
				a.Bugs = append(a.Bugs, Bug{
					BugID:    b.BugID,
					Feedback: b.Feedback,
					Parent:   b.Parent,
					Security: b.Security,
					Title:    b.Title,
				})
			}
			for _, b := range u.Builds {
				a.Builds = append(a.Builds, Build{
					Epoch:     b.Epoch,
					NVR:       b.NVR,
					ReleaseID: b.ReleaseID,
					Signed:    b.Signed,
					Type:      b.Type,
				})
			}

			advs = append(advs, a)
		}
		respChan <- advs

		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "pipeline get")
	}
	close(respChan)

	var advs []Advisory
	for r := range respChan {
		advs = append(advs, r...)
	}

	return advs, nil
}

func (opts options) advisory(client *utilhttp.Client, advisory *Advisory) error {
	for i, build := range advisory.Builds {
		pkgs, mod, err := opts.packages(client, build)
		if err != nil {
			return errors.Wrap(err, "fetch packages")
		}
		advisory.Builds[i].Package = pkgs
		advisory.Builds[i].Module = mod
	}

	for i, bug := range advisory.Bugs {
		b, err := opts.bugzilla(client, fmt.Sprintf(opts.dataURL.Bugzilla, fmt.Sprintf("%d", bug.BugID)))
		if err != nil {
			return errors.Wrap(err, "fetch bugzilla")
		}
		advisory.Bugs[i].Bugzilla = *b
	}

	return nil
}

func (opts options) packages(client *utilhttp.Client, build Build) (map[string][]Package, *Module, error) {
	switch build.Type {
	case "rpm":
		buildID, err := findBuildID(client, opts.dataURL.Package, build.NVR)
		if err != nil {
			return nil, nil, errors.Wrap(err, "findBuildID")
		}

		ps, err := listRPMs(client, opts.dataURL.Package, &buildID, nil)
		if err != nil {
			return nil, nil, errors.Wrap(err, "listRPMs")
		}

		m := make(map[string][]Package)
		for _, p := range ps {
			m[p.Arch] = append(m[p.Arch], p)
		}

		return m, nil, nil
	case "module":
		buildinfo, err := getBuild(client, opts.dataURL.Package, build.NVR)
		if err != nil {
			return nil, nil, errors.Wrap(err, "getBuild")
		}

		if buildinfo.Extra.TypeInfo.Module.IsZero() {
			return nil, nil, errors.Errorf("buildinfo does not have module info. build_id: %q, nvr: %q", buildinfo.ID, build.NVR)
		}

		as, err := listArchives(client, opts.dataURL.Package, buildinfo.ID)
		if err != nil {
			return nil, nil, errors.Wrap(err, "listArchives")
		}

		m := make(map[string][]Package)
		for _, a := range as {
			ps, err := listRPMs(client, opts.dataURL.Package, nil, &a.ID)
			if err != nil {
				return nil, nil, errors.Wrap(err, "listRPMs")
			}
			m[a.Filename] = ps
		}
		return m, &buildinfo.Extra.TypeInfo.Module, nil
	case "flatpak", "container":
		return nil, nil, nil
	default:
		return nil, nil, errors.Errorf("unexpected build type. expected: %q, actual: %q", []string{"rpm", "module", "flatpak", "container"}, build.Type)
	}
}

func findBuildID(client *utilhttp.Client, url, nvr string) (int, error) {
	bs, err := xmlrpc.Marshal("findBuildID", nvr)
	if err != nil {
		return 0, errors.Wrap(err, "marshal xmlrpc body")
	}

	header := make(http.Header)
	header.Set("Accept", "application/xml")
	header.Set("Content-Type", "application/xml")

	req, err := utilhttp.NewRequest(http.MethodPost, url, utilhttp.WithRequestHeader(header), utilhttp.WithRequestBody(bs))
	if err != nil {
		return 0, errors.Wrap(err, "from request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.Wrapf(err, "fetch %#v", req)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return 0, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	bs, err = io.ReadAll(resp.Body)
	if err != nil {
		return 0, errors.Wrap(err, "read all response body")
	}

	var id int
	if err := xmlrpc.Unmarshal(bs, &id); err != nil {
		return 0, errors.Wrap(err, "unmarshal xmlrpc")
	}

	return id, nil
}

func getBuild(client *utilhttp.Client, url string, nvr string) (build, error) {
	bs, err := xmlrpc.Marshal("getBuild", nvr)
	if err != nil {
		return build{}, errors.Wrap(err, "marshal xmlrpc body")
	}

	header := make(http.Header)
	header.Set("Accept", "application/xml")
	header.Set("Content-Type", "application/xml")

	req, err := utilhttp.NewRequest(http.MethodPost, url, utilhttp.WithRequestHeader(header), utilhttp.WithRequestBody(bs))
	if err != nil {
		return build{}, errors.Wrap(err, "from request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return build{}, errors.Wrapf(err, "fetch %#v", req)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return build{}, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	bs, err = io.ReadAll(resp.Body)
	if err != nil {
		return build{}, errors.Wrap(err, "read all response body")
	}

	var b build
	if err := xmlrpc.Unmarshal(bs, &b); err != nil {
		return build{}, errors.Wrap(err, "unmarshal xmlrpc")
	}

	return b, nil
}

func listArchives(client *utilhttp.Client, url string, buildID int) ([]archive, error) {
	bs, err := xmlrpc.Marshal("listArchives", buildID)
	if err != nil {
		return nil, errors.Wrap(err, "marshal xmlrpc body")
	}

	header := make(http.Header)
	header.Set("Accept", "application/xml")
	header.Set("Content-Type", "application/xml")

	req, err := utilhttp.NewRequest(http.MethodPost, url, utilhttp.WithRequestHeader(header), utilhttp.WithRequestBody(bs))
	if err != nil {
		return nil, errors.Wrap(err, "from request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %#v", req)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	bs, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read all response body")
	}

	var as []archive
	if err := xmlrpc.Unmarshal(bs, &as); err != nil {
		return nil, errors.Wrap(err, "unmarshal xmlrpc")
	}

	return as, nil
}

func listRPMs(client *utilhttp.Client, url string, buildID, imageID *int) ([]Package, error) {
	bs, err := xmlrpc.Marshal("listRPMs", buildID, nil, imageID)
	if err != nil {
		return nil, errors.Wrap(err, "marshal xmlrpc body")
	}

	header := make(http.Header)
	header.Set("Accept", "application/xml")
	header.Set("Content-Type", "application/xml")

	req, err := utilhttp.NewRequest(http.MethodPost, url, utilhttp.WithRequestHeader(header), utilhttp.WithRequestBody(bs))
	if err != nil {
		return nil, errors.Wrap(err, "from request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %#v", req)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	bs, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read all response body")
	}

	var ps []Package
	if err := xmlrpc.Unmarshal(bs, &ps); err != nil {
		return nil, errors.Wrap(err, "unmarshal xmlrpc")
	}

	return ps, nil
}

func (opts options) bugzilla(client *utilhttp.Client, url string) (*Bugzilla, error) {
	header := make(http.Header)
	header.Set("Accept", "application/xml")

	req, err := utilhttp.NewRequest(http.MethodGet, url, utilhttp.WithRequestHeader(header))
	if err != nil {
		return nil, errors.Wrap(err, "from request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var b bugzilla
	if err := xml.NewDecoder(resp.Body).Decode(&b); err != nil {
		return nil, errors.Wrap(err, "decode xml")
	}

	bug := Bugzilla{
		BugID:          b.Bug.BugID,
		Error:          b.Bug.Error,
		Alias:          b.Bug.Alias,
		CreationTs:     b.Bug.CreationTs,
		ShortDesc:      b.Bug.ShortDesc,
		DeltaTs:        b.Bug.DeltaTs,
		Classification: b.Bug.Classification,
		Product:        b.Bug.Product,
		Component:      b.Bug.Component,
		Version:        b.Bug.Version,
		RepPlatform:    b.Bug.RepPlatform,
		OpSys:          b.Bug.OpSys,
		BugStatus:      b.Bug.BugStatus,
		Resolution:     b.Bug.Resolution,
		BugFileLoc:     b.Bug.BugFileLoc,
		Keywords:       b.Bug.Keywords,
		Priority:       b.Bug.Priority,
		BugSeverity:    b.Bug.BugSeverity,
		DependsOn:      b.Bug.DependsOn,
		ExternalBugs: (*struct {
			Text string "json:\"text,omitempty\""
			Name string "json:\"name,omitempty\""
		})(b.Bug.ExternalBugs),
		LongDesc: []struct {
			Isprivate    string "json:\"isprivate,omitempty\""
			Commentid    string "json:\"commentid,omitempty\""
			CommentCount string "json:\"comment_count,omitempty\""
			Who          struct {
				Text string "json:\"text,omitempty\""
				Name string "json:\"name,omitempty\""
			} "json:\"who,omitzero\""
			BugWhen string "json:\"bug_when,omitempty\""
			Thetext string "json:\"thetext,omitempty\""
		}(b.Bug.LongDesc),
	}
	for _, blocked := range b.Bug.Blocked {
		bb, err := opts.bugzilla(client, fmt.Sprintf(opts.dataURL.Bugzilla, blocked))
		if err != nil {
			return nil, errors.Wrap(err, "fetch bugzilla")
		}
		bug.Blocked = append(bug.Blocked, *bb)
	}

	return &bug, nil
}
