// Package officec2r extracts the fetched "Release notes for Microsoft 365 Apps
// security updates" into fixed-build criteria for the Office Click-to-Run
// products. MSRC CVRF gives these products no fixed build (its Vendor Fix
// points at the release notes), so microsoft-cvrf emits no criterion for them
// and this data source carries their detection instead.
//
// For every CVE (or ADV) the page lists, each product family takes the first
// release entry (oldest) that lists the ID and has a build line for the
// family. Every build branch the entry lists for the family becomes a range
// [16.0.<branch>.0, 16.0.<branch>.<revision>), the revision being the lowest
// one the entry lists for that branch across the family's channels, so that a
// host on any fixed build of the branch is not flagged. Volume-licensed lines
// keep one version (1808, 2108, 2408) while their build number moves on every
// month, so they form one band per channel and version instead, starting at
// the lowest build the page ever lists for it.
//
// The page does not say which products a CVE affects: an entry lists every
// line released that month. A product family is therefore emitted for a CVE
// whenever the entry carries a line of the family, which may name products
// MSRC does not list as affected.
package officec2r

import (
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	officewindowsversion "github.com/MaineK00n/go-microsoft-version/office/windows"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	criterionpackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/extract/util/filepath"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/officec2r"
)

const releaseNotesURL = "https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates"

type options struct {
	dir string
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

type family string

const (
	familyM365 family = "Microsoft 365 Apps"
	family2016 family = "Office 2016"
	family2019 family = "Office 2019"
	family2021 family = "Office LTSC 2021"
	family2024 family = "Office LTSC 2024"
)

type line struct {
	family family
	// volumeLicensed lines stay on one version and move their build number
	// every month (e.g. Office 2019 1808: 10364.x in 2020-Aug ... 10417.x in 2026).
	volumeLicensed bool
}

// channels maps every channel name the page uses to its product family.
// A name not listed here fails the extraction.
var channels = map[string]line{
	"Current Channel":                          {family: familyM365},
	"Monthly Channel":                          {family: familyM365},
	"Monthly Enterprise Channel":               {family: familyM365},
	"Semi-Annual Channel":                      {family: familyM365},
	"Semi-Annual Channel (Targeted)":           {family: familyM365},
	"Semi-Annual Targeted Channel":             {family: familyM365},
	"Semi-Annual Enterprise Channel":           {family: familyM365},
	"Semi-Annual Enterprise Channel (Preview)": {family: familyM365},
	"Semi-Annual Enterprise Channel (receives Monthly Enterprise Channel builds)": {family: familyM365},
	"Microsoft 365 Apps on Windows 7":                                             {family: familyM365},

	"Office 2016 Retail": {family: family2016},

	"Office 2019 Retail":          {family: family2019},
	"Office 2019 Volume Licensed": {family: family2019, volumeLicensed: true},

	"Office 2021 Retail":               {family: family2021},
	"Office LTSC 2021 Volume Licensed": {family: family2021, volumeLicensed: true},

	"Office 2024 Retail":               {family: family2024},
	"Office LTSC 2024 Volume Licensed": {family: family2024, volumeLicensed: true},
}

// proPlusRenamed is when MSRC CVRF switched from "Office 365 ProPlus" to
// "Microsoft 365 Apps for Enterprise": the last ProPlus document is 2020-Apr,
// the first Microsoft 365 Apps one 2020-May.
var proPlusRenamed = time.Date(2020, time.May, 1, 0, 0, 0, 0, time.UTC)

// products returns the MSRC CVRF product names (32-bit, 64-bit) of a family.
func products(f family, date time.Time) []string {
	switch f {
	case familyM365:
		if date.Before(proPlusRenamed) {
			return []string{"Office 365 ProPlus for 32-bit Systems", "Office 365 ProPlus for 64-bit Systems"}
		}
		return []string{"Microsoft 365 Apps for Enterprise for 32-bit Systems", "Microsoft 365 Apps for Enterprise for 64-bit Systems"}
	case family2016:
		return []string{"Microsoft Office 2016 Click-to-Run (C2R) for 32-bit editions", "Microsoft Office 2016 Click-to-Run (C2R) for 64-bit editions"}
	case family2019:
		return []string{"Microsoft Office 2019 for 32-bit editions", "Microsoft Office 2019 for 64-bit editions"}
	case family2021:
		return []string{"Microsoft Office LTSC 2021 for 32-bit editions", "Microsoft Office LTSC 2021 for 64-bit editions"}
	case family2024:
		return []string{"Microsoft Office LTSC 2024 for 32-bit editions", "Microsoft Office LTSC 2024 for 64-bit editions"}
	default:
		return nil
	}
}

var (
	idRE          = regexp.MustCompile(`^(?:CVE-\d{4}-\d{4,}|ADV\d{6})$`)
	idLikeRE      = regexp.MustCompile(`CVE-\d|ADV\d`)
	trailingRE    = regexp.MustCompile(`^\([^()]+\)$`)
	releasedOnRE  = regexp.MustCompile(`^released [A-Z][a-z]+ \d{1,2}, \d{4}$`)
	buildNumberRE = regexp.MustCompile(`^(\d+)\.(\d+)$`)
)

type build struct {
	line     line
	channel  string
	version  string
	branch   int
	revision int
}

type release struct {
	raw    string
	id     string
	date   time.Time
	builds []build
	// ids lists the CVE / ADV IDs of the entry in page order, without duplicates.
	ids []string
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "microsoft", "office-c2r"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Microsoft Office Click-to-Run Security Updates")

	var rs []release
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched officec2r.Release
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		rel, err := parseRelease(fetched)
		if err != nil {
			return errors.Wrapf(err, "parse %s", path)
		}
		rel.raw = r.Paths()[0]
		rs = append(rs, rel)

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	datas, err := extract(rs)
	if err != nil {
		return errors.Wrap(err, "extract")
	}

	for _, data := range datas {
		kind, year, err := idYear(string(data.ID))
		if err != nil {
			return errors.Wrapf(err, "id year of %s", data.ID)
		}

		p, err := utilfilepath.Join(options.dir, "data", kind, year, fmt.Sprintf("%s.json", data.ID))
		if err != nil {
			return errors.Wrap(err, "join")
		}

		if err := util.Write(p, data, true); err != nil {
			return errors.Wrapf(err, "write %s", p)
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MicrosoftOfficeC2R,
		Name: new("Microsoft 365 Apps Security Updates Release Notes"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{
					URL: u,
				}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

func parseRelease(r officec2r.Release) (release, error) {
	date, err := time.Parse("January 2, 2006", r.Date)
	if err != nil {
		return release{}, errors.Wrapf(err, "unexpected date format. expected: %q, actual: %q", "January 2, 2006", r.Date)
	}

	rel := release{id: r.ID, date: date}

	for _, b := range r.Builds {
		l, ok := channels[b.Channel]
		if !ok {
			return release{}, errors.Errorf("unexpected channel. expected: %q, actual: %q", slices.Sorted(maps.Keys(channels)), b.Channel)
		}

		// "rolled back" (2022-08-09: Monthly Enterprise Channel 2206 15330.20298,
		// replaced by 15330.20306 "released August 18, 2022"): the rolled back
		// build carried the fix as well, and the lower revision keeps hosts that
		// installed it from being flagged.
		if b.Note != "" && b.Note != "rolled back" && !releasedOnRE.MatchString(b.Note) {
			return release{}, errors.Errorf("unexpected build note. expected: %q, actual: %q", []string{"", "rolled back", "released <Month> <D>, <YYYY>"}, b.Note)
		}

		m := buildNumberRE.FindStringSubmatch(b.Build)
		if m == nil {
			return release{}, errors.Errorf("unexpected build format. expected: %q, actual: %q", "<branch>.<revision>", b.Build)
		}
		branch, err := strconv.Atoi(m[1])
		if err != nil {
			return release{}, errors.Wrapf(err, "parse branch of %q", b.Build)
		}
		revision, err := strconv.Atoi(m[2])
		if err != nil {
			return release{}, errors.Wrapf(err, "parse revision of %q", b.Build)
		}

		rel.builds = append(rel.builds, build{line: l, channel: b.Channel, version: b.Version, branch: branch, revision: revision})
	}

	seen := make(map[string]struct{})
	for _, s := range r.Sections {
		for _, item := range s.Items {
			var ids []string
			for _, l := range item.Links {
				if idRE.MatchString(l.Text) {
					if !strings.HasSuffix(l.URL, "/"+l.Text) {
						return release{}, errors.Errorf("unexpected advisory link. expected: URL ending with %q, actual: %q", "/"+l.Text, l.URL)
					}
					ids = append(ids, l.Text)
				}
			}

			switch len(ids) {
			case 0:
				// Prose notes (e.g. "The updates this month also provide
				// defense-in-depth security enhancements for Excel. ...").
				if idLikeRE.MatchString(item.Text) {
					return release{}, errors.Errorf("unexpected list item naming an ID without an advisory link: %q", item.Text)
				}
				continue
			case 1:
				rest, ok := strings.CutPrefix(item.Text, ids[0])
				if !ok {
					return release{}, errors.Errorf("unexpected list item. expected: starting with %q, actual: %q", ids[0], item.Text)
				}
				// e.g. "CVE-2021-34478 (Fix was updated for this CVE)"
				if rest = strings.TrimSpace(rest); rest != "" && !trailingRE.MatchString(rest) {
					return release{}, errors.Errorf("unexpected text after %s. expected: %q, actual: %q", ids[0], "(<note>)", rest)
				}
			default:
				return release{}, errors.Errorf("unexpected list item. expected: one advisory link, actual: %q", ids)
			}

			if _, ok := seen[ids[0]]; ok {
				continue
			}
			seen[ids[0]] = struct{}{}
			rel.ids = append(rel.ids, ids[0])
		}
	}

	if len(rel.ids) > 0 && len(rel.builds) == 0 {
		return release{}, errors.Errorf("unexpected release %q. expected: builds for an entry listing fixes", r.Date)
	}

	return rel, nil
}

type vlKey struct {
	channel string
	version string
}

func extract(rs []release) ([]dataTypes.Data, error) {
	slices.SortFunc(rs, func(a, b release) int { return a.date.Compare(b.date) })
	for i := 1; i < len(rs); i++ {
		if rs[i-1].date.Equal(rs[i].date) {
			return nil, errors.Errorf("unexpected duplicate release date. %q and %q are both %s", rs[i-1].id, rs[i].id, rs[i].date.Format("2006-01-02"))
		}
	}

	// floors holds the lowest build branch the page ever lists for a
	// volume-licensed channel and version: the start of its band.
	floors := make(map[vlKey]int)
	for _, r := range rs {
		for _, b := range r.builds {
			if !b.line.volumeLicensed {
				continue
			}
			k := vlKey{channel: b.channel, version: b.version}
			if f, ok := floors[k]; !ok || b.branch < f {
				floors[k] = b.branch
			}
		}
	}

	type usage struct {
		release *release
		family  family
	}
	var order []string
	used := make(map[string][]usage)
	for i := range rs {
		r := &rs[i]
		families := make(map[family]struct{})
		for _, b := range r.builds {
			families[b.line.family] = struct{}{}
		}
		for _, id := range r.ids {
			if _, ok := used[id]; !ok {
				order = append(order, id)
				used[id] = nil
			}
			for _, f := range slices.Sorted(maps.Keys(families)) {
				if slices.ContainsFunc(used[id], func(u usage) bool { return u.family == f }) {
					continue
				}
				used[id] = append(used[id], usage{release: r, family: f})
			}
		}
	}

	datas := make([]dataTypes.Data, 0, len(order))
	for _, id := range order {
		var (
			conditions []conditionTypes.Condition
			segments   []segmentTypes.Segment
			raws       []string
			refs       = []referenceTypes.Reference{{
				Source: "secure@microsoft.com",
				URL:    fmt.Sprintf("https://msrc.microsoft.com/update-guide/vulnerability/%s", id),
			}}
		)
		for _, u := range used[id] {
			cn, err := buildCriterion(u.release.builds, u.family, floors)
			if err != nil {
				return nil, errors.Wrapf(err, "build criterion of %s for %s in %q", id, u.family, u.release.id)
			}
			for _, p := range products(u.family, u.release.date) {
				c := cn
				c.Version = new(*cn.Version)
				c.Version.Affected = &affectedTypes.Affected{
					Type:  cn.Version.Affected.Type,
					Range: slices.Clone(cn.Version.Affected.Range),
					Fixed: slices.Clone(cn.Version.Affected.Fixed),
				}
				c.Version.Package.Binary = &binaryTypes.Package{Name: p}
				conditions = append(conditions, conditionTypes.Condition{
					Criteria: criteriaTypes.Criteria{
						Operator:   criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{c},
					},
					Tag: segmentTypes.DetectionTag(p),
				})
				segments = append(segments, segmentTypes.Segment{Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft, Tag: segmentTypes.DetectionTag(p)})
			}
			if !slices.Contains(raws, u.release.raw) {
				raws = append(raws, u.release.raw)
			}
			ref := referenceTypes.Reference{Source: "learn.microsoft.com", URL: fmt.Sprintf("%s#%s", releaseNotesURL, u.release.id)}
			if !slices.Contains(refs, ref) {
				refs = append(refs, ref)
			}
		}

		data := dataTypes.Data{
			ID: dataTypes.RootID(id),
			Detections: []detectionTypes.Detection{{
				Ecosystem:  ecosystemTypes.EcosystemTypeMicrosoft,
				Conditions: conditions,
			}},
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MicrosoftOfficeC2R,
				Raws: raws,
			},
		}
		switch {
		case strings.HasPrefix(id, "CVE-"):
			data.Vulnerabilities = []vulnerabilityTypes.Vulnerability{{
				Content: vulnerabilityContentTypes.Content{
					ID:         vulnerabilityContentTypes.VulnerabilityID(id),
					References: refs,
				},
				Segments: segments,
			}}
		case strings.HasPrefix(id, "ADV"):
			data.Advisories = []advisoryTypes.Advisory{{
				Content: advisoryContentTypes.Content{
					ID:         advisoryContentTypes.AdvisoryID(id),
					References: refs,
				},
				Segments: segments,
			}}
		default:
			return nil, errors.Errorf("unexpected ID prefix. expected: %q, actual: %q", []string{"CVE-", "ADV"}, id)
		}
		datas = append(datas, data)
	}

	return datas, nil
}

// buildCriterion builds the fixed-build criterion of one family from the build
// lines of one release entry. The binary package name is left for the caller.
func buildCriterion(builds []build, f family, floors map[vlKey]int) (criterionTypes.Criterion, error) {
	type band struct {
		floor    int
		branch   int
		revision int
	}
	branches := make(map[int]int) // retail / Microsoft 365 Apps branch -> lowest revision
	bands := make(map[vlKey]band)
	for _, b := range builds {
		if b.line.family != f {
			continue
		}
		if !b.line.volumeLicensed {
			if r, ok := branches[b.branch]; !ok || b.revision < r {
				branches[b.branch] = b.revision
			}
			continue
		}
		k := vlKey{channel: b.channel, version: b.version}
		if v, ok := bands[k]; ok {
			if v.branch != b.branch {
				return criterionTypes.Criterion{}, errors.Errorf("unexpected volume licensed builds. expected: one branch per channel and version, actual: %d and %d for %s %s", v.branch, b.branch, b.channel, b.version)
			}
			v.revision = min(v.revision, b.revision)
			bands[k] = v
			continue
		}
		bands[k] = band{floor: floors[k], branch: b.branch, revision: b.revision}
	}
	if len(branches) == 0 && len(bands) == 0 {
		return criterionTypes.Criterion{}, errors.New("no build line")
	}

	var (
		ranges []rangeTypes.Range
		fixed  []string
	)
	add := func(lower, branch, revision int) error {
		ge, lt := fmt.Sprintf("16.0.%d.0", lower), fmt.Sprintf("16.0.%d.%d", branch, revision)
		for _, v := range []string{ge, lt} {
			if _, err := officewindowsversion.NewVersion(v); err != nil {
				return errors.Wrapf(err, "officewindowsversion.NewVersion(%q)", v)
			}
		}
		ranges = append(ranges, rangeTypes.Range{GreaterEqual: ge, LessThan: lt})
		fixed = append(fixed, lt)
		return nil
	}
	for _, branch := range slices.Sorted(maps.Keys(branches)) {
		if err := add(branch, branch, branches[branch]); err != nil {
			return criterionTypes.Criterion{}, errors.Wrap(err, "add branch range")
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(bands), func(a, b vlKey) int {
		return strings.Compare(a.channel+"\x00"+a.version, b.channel+"\x00"+b.version)
	}) {
		v := bands[k]
		// A retail branch inside the band would be compared against both ranges.
		for branch := range branches {
			if v.floor <= branch && branch <= v.branch {
				return criterionTypes.Criterion{}, errors.Errorf("unexpected overlap. branch %d lies in the %s %s band [%d, %d]", branch, k.channel, k.version, v.floor, v.branch)
			}
		}
		if err := add(v.floor, v.branch, v.revision); err != nil {
			return criterionTypes.Criterion{}, errors.Wrap(err, "add volume licensed range")
		}
	}

	return criterionTypes.Criterion{
		Type: criterionTypes.CriterionTypeVersion,
		Version: &vcTypes.Criterion{
			Vulnerable: true,
			FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
			Package: criterionpackageTypes.Package{
				Type: criterionpackageTypes.PackageTypeBinary,
			},
			Affected: &affectedTypes.Affected{
				Type:  rangeTypes.RangeTypeMicrosoftOfficeWindows,
				Range: ranges,
				Fixed: fixed,
			},
		},
	}, nil
}

func idYear(id string) (string, string, error) {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		splitted, err := util.Split(id, "-", "-")
		if err != nil {
			return "", "", errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", id)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return "", "", errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", id)
		}
		return "CVE", splitted[1], nil
	case strings.HasPrefix(id, "ADV"):
		t, err := time.Parse("06", id[3:5])
		if err != nil {
			return "", "", errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ADVyy\\d{4}", id)
		}
		return "ADV", fmt.Sprintf("%d", t.Year()), nil
	default:
		return "", "", errors.Errorf("unexpected ID format. expected: %q, actual: %q", []string{"CVE-yyyy-\\d{4,}", "ADVyy\\d{4}"}, id)
	}
}
