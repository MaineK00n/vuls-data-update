package salsa

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	deb "github.com/knqyf263/go-deb-version"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	fetched "github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/salsa"
)

type options struct {
	dir         string
	concurrency int
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

func Extract(root string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "debian", "tracker", "salsa"),
		concurrency: runtime.NumCPU(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Debian Security Tracker Salsa repository")

	pkgs, err := options.walkPackages(root)
	if err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	if err := options.walkCVE(root, pkgs); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	if err := options.walkAdvisory(root); err != nil {
		return errors.Wrapf(err, "walk %s", root)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.DebianSecurityTrackerSalsa,
		Name: new("Debian Security Tracker Salsa"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(root)
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

var codenameToVersion = map[string]string{
	"buzz":         "1.1",
	"rex":          "1.2",
	"bo":           "1.3",
	"hamm":         "2.0",
	"slink":        "2.1",
	"potato":       "2.2",
	"woody":        "3.0",
	"sarge":        "3.1",
	"etch":         "4",
	"lenny":        "5",
	"squeeze":      "6",
	"wheezy":       "7",
	"jessie":       "8",
	"stretch":      "9",
	"buster":       "10",
	"bullseye":     "11",
	"bookworm":     "12",
	"trixie":       "13",
	"forky":        "14",
	"duke":         "15",
	"sid":          "sid",
	"experimental": "experimental",
}

type extractor struct {
	baseDir string
	r       *utiljson.JSONReader
}

func (o options) walkPackages(root string) (map[string]map[string]distribution, error) {
	reqChan := make(chan string)

	eg, ctx := errgroup.WithContext(context.TODO())
	eg.SetLimit(1 + o.concurrency)
	eg.Go(func() error {
		defer close(reqChan)

		return filepath.WalkDir(filepath.Join(root, "packages"), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			select {
			case reqChan <- path:
			case <-ctx.Done():
				return ctx.Err()
			}

			return nil
		})
	})

	resChan := make(chan map[string]map[string]distribution)
	for i := 0; i < o.concurrency; i++ {
		eg.Go(func() error {
			for path := range reqChan {
				r, err := func() (map[string]map[string]distribution, error) {
					rel, err := filepath.Rel(root, path)
					if err != nil {
						return nil, errors.Wrapf(err, "rel %s", path)
					}

					// packages/trixie/stable/main/l/linux.json
					ss := strings.Split(rel, string(os.PathSeparator))
					if len(ss) != 6 {
						return nil, errors.Errorf("unexpected path format. expected: %q, actual: %q", "packages/<ecosystem>/<repository>/<section>/<package name first letter>/<package name>.json", rel)
					}

					switch ss[2] {
					case "stable":
						return map[string]map[string]distribution{strings.TrimSuffix(ss[5], ".json"): {ss[1]: {Stable: path}}}, nil
					case "security":
						return map[string]map[string]distribution{strings.TrimSuffix(ss[5], ".json"): {ss[1]: {Security: path}}}, nil
					case "backport":
						return map[string]map[string]distribution{strings.TrimSuffix(ss[5], ".json"): {ss[1]: {Backport: path}}}, nil
					default:
						return nil, errors.Errorf("unexpected package repository. expected: %q, actual: %q", []string{"stable", "security", "backport"}, ss[2])
					}
				}()
				if err != nil {
					return errors.Wrapf(err, "read package %s", path)
				}

				select {
				case resChan <- r:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}

	go func() {
		eg.Wait() //nolint:errcheck
		close(resChan)
	}()

	m := make(map[string]map[string]distribution)
	for r := range resChan {
		for pkg, codes := range r {
			if _, ok := m[pkg]; !ok {
				m[pkg] = make(map[string]distribution)
			}
			for code, path := range codes {
				base := m[pkg][code]
				if path.Stable != "" {
					base.Stable = path.Stable
				}
				if path.Security != "" {
					base.Security = path.Security
				}
				// ignore backport repositories as they are uncommon
				// if path.Backport != "" {
				// 	base.Backport = path.Backport
				// }
				m[pkg][code] = base
			}
		}
	}

	if err := eg.Wait(); err != nil {
		return nil, errors.Wrapf(err, "wait for walk")
	}

	return m, nil
}

func (o options) walkCVE(root string, pkgs map[string]map[string]distribution) error {
	reqChan := make(chan string)

	eg, ctx := errgroup.WithContext(context.TODO())
	eg.SetLimit(1 + o.concurrency)
	eg.Go(func() error {
		defer close(reqChan)

		return filepath.WalkDir(filepath.Join(root, "CVE"), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			select {
			case reqChan <- path:
			case <-ctx.Done():
				return ctx.Err()
			}

			return nil
		})
	})

	for i := 0; i < o.concurrency; i++ {
		eg.Go(func() error {
			for path := range reqChan {
				d, err := (extractor{
					baseDir: root,
					r:       utiljson.NewJSONReader(),
				}).extractCVE(path, pkgs)
				if err != nil {
					return errors.Wrapf(err, "extract %s", path)
				}

				splitted, err := util.Split(string(d.ID), "-", "-")
				if err != nil {
					return errors.Errorf("unexpected vulnerability id format. expected: %q, actual: %q", []string{"CVE-yyyy-\\d{4,}", "TEMP-\\d+-\\d+"}, d.ID)
				}

				switch splitted[0] {
				case "CVE":
					if err := util.Write(filepath.Join(o.dir, "data", "CVE", splitted[1], fmt.Sprintf("%s.json", d.ID)), d, true); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(o.dir, "data", "CVE", splitted[1], fmt.Sprintf("%s.json", d.ID)))
					}
				case "TEMP":
					if err := util.Write(filepath.Join(o.dir, "data", splitted[0], fmt.Sprintf("%s.json", d.ID)), d, true); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(o.dir, "data", splitted[0], fmt.Sprintf("%s.json", d.ID)))
					}
				default:
					return errors.Errorf("unexpected vulnerability id format. expected: %q, actual: %q", []string{"CVE-yyyy-\\d{4,}", "TEMP-\\d+-\\d+"}, d.ID)
				}
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return errors.Wrapf(err, "wait for walk")
	}

	return nil
}

func (o options) walkAdvisory(root string) error {
	for _, dir := range []string{"DSA", "DLA", "DTSA"} {
		reqChan := make(chan string)

		eg, ctx := errgroup.WithContext(context.TODO())
		eg.SetLimit(1 + o.concurrency)
		eg.Go(func() error {
			defer close(reqChan)

			return filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() || filepath.Ext(path) != ".json" {
					return nil
				}

				select {
				case reqChan <- path:
				case <-ctx.Done():
					return ctx.Err()
				}

				return nil
			})
		})

		for i := 0; i < o.concurrency; i++ {
			eg.Go(func() error {
				for path := range reqChan {
					d, skip, err := (extractor{
						baseDir: root,
						r:       utiljson.NewJSONReader(),
					}).extractAdvisory(path)
					if err != nil {
						return errors.Wrapf(err, "extract %s", path)
					}
					if skip {
						continue
					}

					splitted, err := util.Split(string(d.ID), "-")
					if err != nil {
						return errors.Errorf("unexpected advisory id format. expected: %q, actual: %q", []string{"DSA-\\d+(-\\d+)?", "DLA-\\d+-\\d+", "DTSA-\\d+-\\d+"}, d.ID)
					}

					switch splitted[0] {
					case "DSA", "DLA", "DTSA":
						if err := util.Write(filepath.Join(o.dir, "data", splitted[0], fmt.Sprintf("%s.json", d.ID)), d, true); err != nil {
							return errors.Wrapf(err, "write %s", filepath.Join(o.dir, "data", splitted[0], fmt.Sprintf("%s.json", d.ID)))
						}
					default:
						return errors.Errorf("unexpected advisory id format. expected: %q, actual: %q", []string{"DSA-\\d+(-\\d+)?", "DLA-\\d+-\\d+", "DTSA-\\d+-\\d+"}, d.ID)
					}
				}
				return nil
			})
		}

		if err := eg.Wait(); err != nil {
			return errors.Wrapf(err, "wait for walk %s", dir)
		}
	}

	return nil
}

func (e extractor) extractAdvisory(path string) (dataTypes.Data, bool, error) {
	baseAC, xrefAnns, apkgs, err := e.readAdvisory(path)
	if err != nil {
		return dataTypes.Data{}, false, errors.Wrapf(err, "read %s", path)
	}

	for _, xref := range xrefAnns {
		for _, bug := range xref.Bugs {
			if strings.HasPrefix(bug, "CVE-") || strings.HasPrefix(bug, "TEMP-") {
				return dataTypes.Data{}, true, nil
			}
		}
	}

	annsByRelease := make(map[string]map[string]cveAnnotation)
	for _, apkg := range apkgs {
		switch apkg.Release {
		case "":
			return dataTypes.Data{}, false, errors.Errorf("unexpected package annotation release. expected: %q, actual: %q", slices.Collect(maps.Keys(codenameToVersion)), apkg.Release)
		default:
			if annsByRelease[apkg.Release] == nil {
				annsByRelease[apkg.Release] = make(map[string]cveAnnotation)
			}
			base := annsByRelease[apkg.Release][apkg.Package]
			if base.Advisories == nil {
				base.Advisories = make(map[string]contentAnnotation[advisoryContentTypes.Content])
			}
			adv := base.Advisories[string(baseAC.ID)]
			adv.Content = baseAC
			adv.Anns = append(adv.Anns, apkg)
			base.Advisories[string(baseAC.ID)] = adv
			annsByRelease[apkg.Release][apkg.Package] = base
		}
	}

	if len(annsByRelease) == 0 {
		return dataTypes.Data{
			ID:         dataTypes.RootID(baseAC.ID),
			Advisories: []advisoryTypes.Advisory{{Content: baseAC}},
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.DebianSecurityTrackerSalsa,
				Raws: e.r.Paths(),
			},
		}, false, nil
	}

	d := dataTypes.Data{ID: dataTypes.RootID(baseAC.ID)}

	for code, annotationsByPkg := range annsByRelease {
		ver, ok := codenameToVersion[code]
		if !ok {
			return dataTypes.Data{}, false, errors.Errorf("unexpected release code name. expected: %q, actual: %q", slices.Collect(maps.Keys(codenameToVersion)), code)
		}

		for pkg, ann := range annotationsByPkg {
			eco := ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeDebian, ver))

			c, err := e.buildCondition(pkg, code, ann, nil)
			if err != nil {
				return dataTypes.Data{}, false, errors.Wrapf(err, "create condition for %q from annotation: %+v", pkg, ann)
			}

			var seg *segmentTypes.Segment
			if c != nil {
				d.Detections = appendDetection(d.Detections, eco, *c)
				seg = &segmentTypes.Segment{
					Ecosystem: eco,
					Tag:       segmentTypes.DetectionTag(pkg),
				}
			}

			for aid, a := range ann.Advisories {
				sev, bugRefs, err := collectSeverityAndBugRefs(a.Anns)
				if err != nil {
					return dataTypes.Data{}, false, errors.Wrapf(err, "collect severity and bug refs for advisory %q pkg %q", aid, pkg)
				}
				if sev != nil {
					a.Content.Severity = []severityTypes.Severity{{
						Type:   severityTypes.SeverityTypeVendor,
						Source: "security-tracker.debian.org",
						Vendor: sev,
					}}
				}
				a.Content.References = append(a.Content.References, bugRefs...)
				d.Advisories = appendOrMergeAdvisory(d.Advisories, a.Content, seg)
			}
		}
	}

	d.DataSource = sourceTypes.Source{
		ID:   sourceTypes.DebianSecurityTrackerSalsa,
		Raws: e.r.Paths(),
	}

	return d, false, nil
}

type distribution struct {
	Stable   string
	Security string
	Backport string
}

type contentAnnotation[T any] struct {
	Content T
	Anns    []packageAnnotation
}

type cveAnnotation struct {
	Vulnerability contentAnnotation[vulnerabilityContentTypes.Content]
	Advisories    map[string]contentAnnotation[advisoryContentTypes.Content]
}

func (e extractor) extractCVE(path string, pkgs map[string]map[string]distribution) (dataTypes.Data, error) {
	annsByRelease := make(map[string]map[string]cveAnnotation)

	baseVC, vxrefs, vpkgs, err := e.readCVE(path)
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "read %s", path)
	}

	for _, vxref := range vxrefs {
		for _, vid := range vxref.Bugs {
			switch {
			case strings.HasPrefix(vid, "CVE-"):
				baseVC.References = append(baseVC.References, referenceTypes.Reference{
					Source: "security-tracker.debian.org",
					URL:    fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", vid),
				})
			case strings.HasPrefix(vid, "DTSA-"), strings.HasPrefix(vid, "DLA-"), strings.HasPrefix(vid, "DSA-"):
				am, err := e.collectAdvisoryAnnotations(vid)
				if err != nil {
					return dataTypes.Data{}, errors.Wrapf(err, "collect advisory annotations for %q", vid)
				}
				for release, pkgAnns := range am {
					if annsByRelease[release] == nil {
						annsByRelease[release] = make(map[string]cveAnnotation)
					}
					for pkg, ann := range pkgAnns {
						base := annsByRelease[release][pkg]
						if base.Advisories == nil {
							base.Advisories = make(map[string]contentAnnotation[advisoryContentTypes.Content])
						}
						for id, adv := range ann.Advisories {
							existing := base.Advisories[id]
							existing.Content = adv.Content
							existing.Anns = append(existing.Anns, adv.Anns...)
							base.Advisories[id] = existing
						}
						annsByRelease[release][pkg] = base
					}
				}
			default:
				return dataTypes.Data{}, errors.Errorf("unexpected xref bug id format. expected: %q, actual: %q", []string{"CVE-...", "DTSA-...", "DLA-...", "DSA-..."}, vid)
			}
		}
	}

	for _, vpkg := range vpkgs {
		if vpkg.Kind == "itp" {
			continue
		}
		switch vpkg.Release {
		case "":
			for code := range pkgs[vpkg.Package] {
				if annsByRelease[code] == nil {
					annsByRelease[code] = make(map[string]cveAnnotation)
				}
				base := annsByRelease[code][vpkg.Package]
				base.Vulnerability.Content = baseVC
				base.Vulnerability.Anns = append(base.Vulnerability.Anns, vpkg)
				annsByRelease[code][vpkg.Package] = base

				// Although the contents of the file are not read, it is assumed that the file exists, i.e. the package exists, so it is read once to mark it in the paths
				if pkgs[vpkg.Package][code].Stable != "" {
					var a any
					if err := e.r.Read(pkgs[vpkg.Package][code].Stable, e.baseDir, &a); err != nil {
						return dataTypes.Data{}, errors.Wrap(err, "read")
					}
				}
				if pkgs[vpkg.Package][code].Security != "" {
					var a any
					if err := e.r.Read(pkgs[vpkg.Package][code].Security, e.baseDir, &a); err != nil {
						return dataTypes.Data{}, errors.Wrap(err, "read")
					}
				}
			}
		default:
			if annsByRelease[vpkg.Release] == nil {
				annsByRelease[vpkg.Release] = make(map[string]cveAnnotation)
			}
			base := annsByRelease[vpkg.Release][vpkg.Package]
			base.Vulnerability.Content = baseVC
			base.Vulnerability.Anns = append(base.Vulnerability.Anns, vpkg)
			annsByRelease[vpkg.Release][vpkg.Package] = base
		}
	}

	if len(annsByRelease) == 0 {
		return dataTypes.Data{
			ID:              dataTypes.RootID(baseVC.ID),
			Vulnerabilities: []vulnerabilityTypes.Vulnerability{{Content: baseVC}},
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.DebianSecurityTrackerSalsa,
				Raws: e.r.Paths(),
			},
		}, nil
	}

	d := dataTypes.Data{ID: dataTypes.RootID(baseVC.ID)}

	for code, annotationsByPkg := range annsByRelease {
		ver, ok := codenameToVersion[code]
		if !ok {
			return dataTypes.Data{}, errors.Errorf("unexpected release code name. expected: %q, actual: %q", slices.Collect(maps.Keys(codenameToVersion)), code)
		}

		for pkg, ann := range annotationsByPkg {
			if len(ann.Advisories) > 0 && ann.Vulnerability.Content.ID == "" {
				ann.Vulnerability.Content = baseVC
			}

			eco := ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeDebian, ver))

			c, err := e.buildCondition(pkg, code, ann, pkgs)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "create condition for %q from annotation: %+v", pkg, ann)
			}

			var seg *segmentTypes.Segment
			if c != nil {
				d.Detections = appendDetection(d.Detections, eco, *c)
				seg = &segmentTypes.Segment{
					Ecosystem: eco,
					Tag:       segmentTypes.DetectionTag(pkg),
				}
			}

			sev, bugRefs, err := collectSeverityAndBugRefs(ann.Vulnerability.Anns)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "collect severity and bug refs for vulnerability %q pkg %q", ann.Vulnerability.Content.ID, pkg)
			}
			if sev != nil {
				ann.Vulnerability.Content.Severity = []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "security-tracker.debian.org",
					Vendor: sev,
				}}
			}
			ann.Vulnerability.Content.References = append(ann.Vulnerability.Content.References, bugRefs...)
			d.Vulnerabilities = appendOrMergeVulnerability(d.Vulnerabilities, ann.Vulnerability.Content, seg)

			for aid, a := range ann.Advisories {
				sev, bugRefs, err := collectSeverityAndBugRefs(a.Anns)
				if err != nil {
					return dataTypes.Data{}, errors.Wrapf(err, "collect severity and bug refs for advisory %q pkg %q", aid, pkg)
				}
				if sev != nil {
					a.Content.Severity = []severityTypes.Severity{{
						Type:   severityTypes.SeverityTypeVendor,
						Source: "security-tracker.debian.org",
						Vendor: sev,
					}}
				}
				a.Content.References = append(a.Content.References, bugRefs...)
				d.Advisories = appendOrMergeAdvisory(d.Advisories, a.Content, seg)
			}
		}
	}

	d.DataSource = sourceTypes.Source{
		ID:   sourceTypes.DebianSecurityTrackerSalsa,
		Raws: e.r.Paths(),
	}

	return d, nil
}

func (e extractor) collectAdvisoryAnnotations(vid string) (map[string]map[string]cveAnnotation, error) {
	dir, _, _ := strings.Cut(vid, "-")
	baseAC, _, apkgs, err := e.readAdvisory(filepath.Join(e.baseDir, dir, fmt.Sprintf("%s.json", vid)))
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", filepath.Join(e.baseDir, dir, fmt.Sprintf("%s.json", vid)))
	}

	annsByRelease := make(map[string]map[string]cveAnnotation)
	for _, apkg := range apkgs {
		if apkg.Release == "" {
			return nil, errors.Errorf("unexpected package annotation release. expected: %q, actual: %q", slices.Collect(maps.Keys(codenameToVersion)), apkg.Release)
		}
		if annsByRelease[apkg.Release] == nil {
			annsByRelease[apkg.Release] = make(map[string]cveAnnotation)
		}
		base := annsByRelease[apkg.Release][apkg.Package]
		if base.Advisories == nil {
			base.Advisories = make(map[string]contentAnnotation[advisoryContentTypes.Content])
		}
		adv := base.Advisories[string(baseAC.ID)]
		adv.Content = baseAC
		adv.Anns = append(adv.Anns, apkg)
		base.Advisories[string(baseAC.ID)] = adv
		annsByRelease[apkg.Release][apkg.Package] = base
	}
	return annsByRelease, nil
}

func newCondition(pkg string, vc vcTypes.Criterion) *conditionTypes.Condition {
	return &conditionTypes.Condition{
		Criteria: criteriaTypes.Criteria{
			Operator: criteriaTypes.CriteriaOperatorTypeOR,
			Criterions: []criterionTypes.Criterion{{
				Type:    criterionTypes.CriterionTypeVersion,
				Version: &vc,
			}},
		},
		Tag: segmentTypes.DetectionTag(pkg),
	}
}

func newFixedCondition(pkg, fixVersion string) *conditionTypes.Condition {
	return newCondition(pkg, vcTypes.Criterion{
		Vulnerable: true,
		FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
		Package: vcPackageTypes.Package{
			Type:   vcPackageTypes.PackageTypeSource,
			Source: &vcSourcePackageTypes.Package{Name: pkg},
		},
		Affected: &vcAffectedTypes.Affected{
			Type:  vcAffectedRangeTypes.RangeTypeDPKG,
			Range: []vcAffectedRangeTypes.Range{{LessThan: fixVersion}},
			Fixed: []string{fixVersion},
		},
	})
}

func newUnfixedCondition(pkg, vendor string) *conditionTypes.Condition {
	return newCondition(pkg, vcTypes.Criterion{
		Vulnerable: true,
		FixStatus: &vcFixStatusTypes.FixStatus{
			Class:  vcFixStatusTypes.ClassUnfixed,
			Vendor: vendor,
		},
		Package: vcPackageTypes.Package{
			Type:   vcPackageTypes.PackageTypeSource,
			Source: &vcSourcePackageTypes.Package{Name: pkg},
		},
	})
}

func newNotAffectedCondition(pkg, vendor string) *conditionTypes.Condition {
	return newCondition(pkg, vcTypes.Criterion{
		Vulnerable: false,
		FixStatus: &vcFixStatusTypes.FixStatus{
			Class:  vcFixStatusTypes.ClassNotAffected,
			Vendor: vendor,
		},
		Package: vcPackageTypes.Package{
			Type:   vcPackageTypes.PackageTypeSource,
			Source: &vcSourcePackageTypes.Package{Name: pkg},
		},
	})
}

func newUnknownCondition(pkg, vendor string) *conditionTypes.Condition {
	return newCondition(pkg, vcTypes.Criterion{
		Vulnerable: false,
		FixStatus: &vcFixStatusTypes.FixStatus{
			Class:  vcFixStatusTypes.ClassUnknown,
			Vendor: vendor,
		},
		Package: vcPackageTypes.Package{
			Type:   vcPackageTypes.PackageTypeSource,
			Source: &vcSourcePackageTypes.Package{Name: pkg},
		},
	})
}

func (e extractor) buildCondition(pkg, code string, ann cveAnnotation, pkgs map[string]map[string]distribution) (*conditionTypes.Condition, error) {
	advs := make(map[string][]packageAnnotation)
	for id, a := range ann.Advisories {
		advs[id] = a.Anns
	}
	max := maxPackageAnnotation(ann.Vulnerability.Anns, advs)

	switch max.Kind {
	case "fixed":
		switch max.Release {
		case "":
			return e.buildFixedConditionWithVersionCheck(pkg, code, max.Version, pkgs)
		default:
			return newFixedCondition(pkg, max.Version), nil
		}
	case "postponed", "end-of-life", "removed", "ignored", "no-dsa", "unfixed":
		vendor := max.Kind
		if max.Description != "" {
			vendor = fmt.Sprintf("%s: %s", max.Kind, max.Description)
		}
		return newUnfixedCondition(pkg, vendor), nil
	case "not-affected":
		vendor := max.Kind
		if max.Description != "" {
			vendor = fmt.Sprintf("%s: %s", max.Kind, max.Description)
		}
		return newNotAffectedCondition(pkg, vendor), nil
	case "itp":
		return nil, nil
	case "undetermined":
		vendor := max.Kind
		if max.Description != "" {
			vendor = fmt.Sprintf("%s: %s", max.Kind, max.Description)
		}
		return newUnknownCondition(pkg, vendor), nil
	default:
		return nil, errors.Errorf("unexpected package annotation kind. expected: %q, actual: %q", []string{"fixed", "postponed", "end-of-life", "removed", "ignored", "no-dsa", "unfixed", "itp", "not-affected", "undetermined"}, max.Kind)
	}
}

func (e extractor) buildFixedConditionWithVersionCheck(pkg, code, fixVersion string, pkgs map[string]map[string]distribution) (*conditionTypes.Condition, error) {
	stablever, stablestatus, err := e.comparePackageVersion(pkgs[pkg][code].Stable, fixVersion)
	if err != nil {
		return nil, errors.Wrapf(err, "compare stable version for %s in %s", pkg, code)
	}

	securityver, securitystatus, err := e.comparePackageVersion(pkgs[pkg][code].Security, fixVersion)
	if err != nil {
		return nil, errors.Wrapf(err, "compare security version for %s in %s", pkg, code)
	}

	switch {
	case stablestatus == nil && securitystatus == nil:
		// backport only
		return nil, nil
	case stablestatus != nil && securitystatus == nil:
		if *stablestatus < 0 {
			return newUnfixedCondition(pkg, fmt.Sprintf("upstream fixed version: %q, %s version: %q", fixVersion, code, stablever)), nil
		}
		return newFixedCondition(pkg, fixVersion), nil
	case stablestatus == nil && securitystatus != nil:
		if *securitystatus < 0 {
			return newUnfixedCondition(pkg, fmt.Sprintf("upstream fixed version: %q, %s-security version: %q", fixVersion, code, securityver)), nil
		}
		return newFixedCondition(pkg, fixVersion), nil
	default:
		if *stablestatus < 0 && *securitystatus < 0 {
			return newUnfixedCondition(pkg, fmt.Sprintf("upstream fixed version: %q, %s version: %q, %s-security version: %q", fixVersion, code, stablever, code, securityver)), nil
		}
		return newFixedCondition(pkg, fixVersion), nil
	}
}

func (e extractor) comparePackageVersion(path, fixVersion string) (string, *int, error) {
	if path == "" {
		return "", nil, nil
	}
	ver, err := e.readPackage(path)
	if err != nil {
		return "", nil, errors.Wrapf(err, "read %s", path)
	}
	status := vercmp(ver, fixVersion)
	return ver, &status, nil
}

func appendDetection(detections []detectionTypes.Detection, eco ecosystemTypes.Ecosystem, c conditionTypes.Condition) []detectionTypes.Detection {
	switch i := slices.IndexFunc(detections, func(e detectionTypes.Detection) bool { return e.Ecosystem == eco }); i {
	case -1:
		return append(detections, detectionTypes.Detection{
			Ecosystem:  eco,
			Conditions: []conditionTypes.Condition{c},
		})
	default:
		detections[i].Conditions = append(detections[i].Conditions, c)
		return detections
	}
}

func collectSeverityAndBugRefs(anns []packageAnnotation) (*string, []referenceTypes.Reference, error) {
	sev, err := maxSeverity(anns)
	if err != nil {
		return nil, nil, errors.Wrap(err, "max severity")
	}

	var refs []referenceTypes.Reference
	for _, ann := range anns {
		for _, f := range ann.Flags {
			if f.Bug != nil {
				r := referenceTypes.Reference{
					Source: "security-tracker.debian.org",
					URL:    fmt.Sprintf("https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=%d", *f.Bug),
				}
				if !slices.Contains(refs, r) {
					refs = append(refs, r)
				}
			}
		}
	}
	return sev, refs, nil
}

func appendOrMergeVulnerability(vulns []vulnerabilityTypes.Vulnerability, content vulnerabilityContentTypes.Content, seg *segmentTypes.Segment) []vulnerabilityTypes.Vulnerability {
	switch i := slices.IndexFunc(vulns, func(e vulnerabilityTypes.Vulnerability) bool {
		return vulnerabilityContentTypes.Compare(e.Content, content) == 0
	}); i {
	case -1:
		v := vulnerabilityTypes.Vulnerability{Content: content}
		if seg != nil {
			v.Segments = []segmentTypes.Segment{*seg}
		}
		return append(vulns, v)
	default:
		if seg != nil {
			vulns[i].Segments = append(vulns[i].Segments, *seg)
		}
		return vulns
	}
}

func appendOrMergeAdvisory(advisories []advisoryTypes.Advisory, content advisoryContentTypes.Content, seg *segmentTypes.Segment) []advisoryTypes.Advisory {
	switch i := slices.IndexFunc(advisories, func(e advisoryTypes.Advisory) bool {
		return advisoryContentTypes.Compare(e.Content, content) == 0
	}); i {
	case -1:
		a := advisoryTypes.Advisory{Content: content}
		if seg != nil {
			a.Segments = []segmentTypes.Segment{*seg}
		}
		return append(advisories, a)
	default:
		if seg != nil {
			advisories[i].Segments = append(advisories[i].Segments, *seg)
		}
		return advisories
	}
}

func (e extractor) readCVE(path string) (vulnerabilityContentTypes.Content, []fetched.XrefAnnotation, []packageAnnotation, error) {
	var b bug
	if err := e.r.Read(path, e.baseDir, &b); err != nil {
		return vulnerabilityContentTypes.Content{}, nil, nil, errors.Wrap(err, "read")
	}
	if b.Header == nil {
		return vulnerabilityContentTypes.Content{}, nil, nil, errors.New("missing header")
	}

	var (
		desc     strings.Builder
		xrefAnns []fetched.XrefAnnotation
		pkgAnns  []packageAnnotation
		notes    []string
		todos    []string
		notForUs []string
	)
	for _, a := range b.Annotations {
		var ann baseAnnotation
		if err := json.Unmarshal(a, &ann); err != nil {
			return vulnerabilityContentTypes.Content{}, nil, nil, errors.Wrap(err, "unmarshal annotation")
		}

		switch ann.Type {
		case "RESERVED", "REJECTED":
			return vulnerabilityContentTypes.Content{
				ID:          vulnerabilityContentTypes.VulnerabilityID(b.Header.Name),
				Description: ann.Type,
				References: []referenceTypes.Reference{{
					Source: "security-tracker.debian.org",
					URL:    fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", b.Header.Name),
				}},
			}, nil, nil, nil
		case "xref":
			var xrefAnn fetched.XrefAnnotation
			if err := json.Unmarshal(a, &xrefAnn); err != nil {
				return vulnerabilityContentTypes.Content{}, nil, nil, errors.Wrap(err, "unmarshal xref annotation")
			}
			xrefAnns = append(xrefAnns, xrefAnn)
		case "package":
			var pkgAnn packageAnnotation
			if err := json.Unmarshal(a, &pkgAnn); err != nil {
				return vulnerabilityContentTypes.Content{}, nil, nil, errors.Wrap(err, "unmarshal package annotation")
			}
			pkgAnns = append(pkgAnns, pkgAnn)
		case "NOTE":
			var noteAnn fetched.StringAnnotation
			if err := json.Unmarshal(a, &noteAnn); err != nil {
				return vulnerabilityContentTypes.Content{}, nil, nil, errors.Wrap(err, "unmarshal note annotation")
			}
			notes = append(notes, noteAnn.Description)
		case "TODO":
			var todoAnn fetched.StringAnnotation
			if err := json.Unmarshal(a, &todoAnn); err != nil {
				return vulnerabilityContentTypes.Content{}, nil, nil, errors.Wrap(err, "unmarshal todo annotation")
			}
			todos = append(todos, todoAnn.Description)
		case "NOT-FOR-US":
			var notForUsAnn fetched.StringAnnotation
			if err := json.Unmarshal(a, &notForUsAnn); err != nil {
				return vulnerabilityContentTypes.Content{}, nil, nil, errors.Wrap(err, "unmarshal not-for-us annotation")
			}
			notForUs = append(notForUs, notForUsAnn.Description)
		default:
			return vulnerabilityContentTypes.Content{}, nil, nil, errors.Errorf("unexpected annotation type. expected: %q, actual: %q", []string{"TODO", "RESERVED", "REJECTED", "NOT-FOR-US", "xref", "package", "NOTE"}, ann.Type)
		}
	}

	if s := strings.TrimPrefix(strings.TrimSuffix(b.Header.Description, ")"), "("); s != "" {
		desc.WriteString(s)
	}
	if len(notes) > 0 {
		fmt.Fprintf(&desc, "\n\nNOTE:\n%s", strings.Join(notes, "\n"))
	}
	if len(todos) > 0 {
		fmt.Fprintf(&desc, "\n\nTODO:\n%s", strings.Join(todos, "\n"))
	}
	if len(notForUs) > 0 {
		fmt.Fprintf(&desc, "\n\nNOT-FOR-US:\n%s", strings.Join(notForUs, "\n"))
	}

	return vulnerabilityContentTypes.Content{
		ID:          vulnerabilityContentTypes.VulnerabilityID(b.Header.Name),
		Description: desc.String(),
		References: []referenceTypes.Reference{{
			Source: "security-tracker.debian.org",
			URL:    fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", b.Header.Name),
		}},
	}, xrefAnns, pkgAnns, nil
}

func (e extractor) readAdvisory(path string) (advisoryContentTypes.Content, []fetched.XrefAnnotation, []packageAnnotation, error) {
	var b bug
	if err := e.r.Read(path, e.baseDir, &b); err != nil {
		return advisoryContentTypes.Content{}, nil, nil, errors.Wrap(err, "read")
	}
	if b.Header == nil {
		return advisoryContentTypes.Content{}, nil, nil, errors.New("missing header")
	}

	var (
		xrefAnns []fetched.XrefAnnotation
		pkgAnns  []packageAnnotation
		notes    []string
	)
	for _, a := range b.Annotations {
		var ann baseAnnotation
		if err := json.Unmarshal(a, &ann); err != nil {
			return advisoryContentTypes.Content{}, nil, nil, errors.Wrap(err, "unmarshal annotation")
		}

		switch ann.Type {
		case "xref":
			var xrefAnn fetched.XrefAnnotation
			if err := json.Unmarshal(a, &xrefAnn); err != nil {
				return advisoryContentTypes.Content{}, nil, nil, errors.Wrapf(err, "unmarshal xref annotation %s", path)
			}
			xrefAnns = append(xrefAnns, xrefAnn)
		case "package":
			var pkgAnn packageAnnotation
			if err := json.Unmarshal(a, &pkgAnn); err != nil {
				return advisoryContentTypes.Content{}, nil, nil, errors.Wrap(err, "unmarshal package annotation")
			}
			pkgAnns = append(pkgAnns, pkgAnn)
		case "NOTE":
			var noteAnn fetched.StringAnnotation
			if err := json.Unmarshal(a, &noteAnn); err != nil {
				return advisoryContentTypes.Content{}, nil, nil, errors.Wrap(err, "unmarshal note annotation")
			}
			notes = append(notes, noteAnn.Description)
		default:
			return advisoryContentTypes.Content{}, nil, nil, errors.Errorf("unexpected annotation type. expected: %q, actual: %q", []string{"xref", "package", "NOTE"}, ann.Type)
		}
	}

	switch {
	case strings.HasPrefix(b.Header.Name, "DTSA-"):
		// [July 3rd, 2008] DTSA-144-1 php5 - Denial of Service
		lhs, rhs, ok := strings.Cut(strings.TrimPrefix(b.Header.Line, "["), "] ")
		if !ok {
			return advisoryContentTypes.Content{}, nil, nil, errors.Errorf("unexpected DTSA header line format. expected: %q, actual: %q", "[Month Dayth, Year] DTSA-XXX-X package - description", b.Header.Line)
		}

		t, err := time.Parse("January 2 2006", strings.NewReplacer("st,", "", "nd,", "", "rd,", "", "th,", "").Replace(lhs))
		if err != nil {
			return advisoryContentTypes.Content{}, nil, nil, errors.Wrapf(err, "parse date")
		}

		return advisoryContentTypes.Content{
			ID: advisoryContentTypes.AdvisoryID(b.Header.Name),
			Description: func() string {
				s := strings.TrimSpace(strings.TrimPrefix(rhs, b.Header.Name))
				if len(notes) > 0 {
					return fmt.Sprintf("%s\n\nNOTE:\n%s", s, strings.Join(notes, "\n"))
				}
				return s
			}(),
			References: []referenceTypes.Reference{{
				Source: "security-tracker.debian.org",
				URL:    fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", b.Header.Name),
			}},
			Published: &t,
		}, xrefAnns, pkgAnns, nil
	case strings.HasPrefix(b.Header.Name, "DLA-"), strings.HasPrefix(b.Header.Name, "DSA-"):
		// [28 Dec 2025] DLA-4423-1 kodi - security update
		// [25 Jan 2026] DSA-6110-1 openjdk-17 - security update
		lhs, rhs, ok := strings.Cut(strings.TrimPrefix(b.Header.Line, "["), "] ")
		if !ok {
			return advisoryContentTypes.Content{}, nil, nil, errors.Errorf("unexpected DLA, DSA header line format. expected: %q, actual: %q", "[Day Month Year] (DLA|DSA)-XXX-X package - description", b.Header.Line)
		}

		t, err := time.Parse("02 Jan 2006", lhs)
		if err != nil {
			return advisoryContentTypes.Content{}, nil, nil, errors.Wrapf(err, "parse date")
		}

		return advisoryContentTypes.Content{
			ID: advisoryContentTypes.AdvisoryID(b.Header.Name),
			Description: func() string {
				s := strings.TrimSpace(strings.TrimPrefix(rhs, b.Header.Name))
				if len(notes) > 0 {
					return fmt.Sprintf("%s\n\nNOTE:\n%s", s, strings.Join(notes, "\n"))
				}
				return s
			}(),
			References: []referenceTypes.Reference{{
				Source: "security-tracker.debian.org",
				URL:    fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", b.Header.Name),
			}},
			Published: &t,
		}, xrefAnns, pkgAnns, nil
	default:
		return advisoryContentTypes.Content{}, nil, nil, errors.Errorf("unexpected header name prefix. expected: %q, actual: %q", []string{"DTSA-", "DLA-", "DSA-", "CVE-"}, b.Header.Name)
	}
}

func (e extractor) readPackage(path string) (string, error) {
	var p map[string][]string
	if err := e.r.Read(path, e.baseDir, &p); err != nil {
		return "", errors.Wrap(err, "read")
	}

	vs, ok := p["Version"]
	if !ok {
		return "", errors.New("Version field not found")
	}
	if len(vs) != 1 {
		return "", errors.Errorf("unexpected number of Version field. expected: %d, actual: %d", 1, len(vs))
	}
	return vs[0], nil
}

func maxPackageAnnotation(cves []packageAnnotation, advs map[string][]packageAnnotation) packageAnnotation {
	kinds := []string{"undetermined", "not-affected", "itp", "unfixed", "no-dsa", "ignored", "removed", "end-of-life", "postponed", "fixed"}

	var pss []packageAnnotation
	pss = append(pss, cves...)
	for _, as := range advs {
		pss = append(pss, as...)
	}

	return slices.MaxFunc(pss, func(a, b packageAnnotation) int {
		return cmp.Or(
			func() int {
				switch {
				case a.Release == "" && b.Release == "":
					return 0
				case a.Release == "" && b.Release != "":
					return -1
				case a.Release != "" && b.Release == "":
					return +1
				default:
					return 0
				}
			}(),
			cmp.Compare(slices.Index(kinds, a.Kind), slices.Index(kinds, b.Kind)),
			func() int {
				switch a.Kind {
				case "fixed":
					return vercmp(a.Version, b.Version)
				default:
					return 0
				}
			}(),
		)
	})
}

func vercmp(a, b string) int {
	va, erra := deb.NewVersion(a)
	vb, errb := deb.NewVersion(b)
	switch {
	case erra != nil && errb != nil:
		return 0
	case erra != nil && errb == nil:
		return -1
	case erra == nil && errb != nil:
		return +1
	default:
		return va.Compare(vb)
	}
}

func maxSeverity(anns []packageAnnotation) (*string, error) {
	// https://security-team.debian.org/security_tracker.html#severity-levels
	severities := []string{"unimportant", "low", "medium", "high"}

	type severityAnnotation struct {
		release  string
		severity string
	}

	filtered := make([]severityAnnotation, 0, len(anns))
	for _, ann := range anns {
		var ss []string
		for _, f := range ann.Flags {
			if f.Severity != nil {
				if !slices.Contains(severities, *f.Severity) {
					return nil, errors.Errorf("unexpected severity. expected: %q, actual: %q", severities, *f.Severity)
				}
				ss = append(ss, *f.Severity)
			}
		}
		switch len(ss) {
		case 0:
		case 1:
			filtered = append(filtered, severityAnnotation{release: ann.Release, severity: ss[0]})
		default:
			return nil, errors.Errorf("multiple severity found in package annotation. expected: %d, actual: %d", []int{0, 1}, len(ss))
		}
	}

	switch len(filtered) {
	case 0:
		return nil, nil
	case 1:
		return &filtered[0].severity, nil
	case 2:
		max := slices.MaxFunc(filtered, func(a, b severityAnnotation) int {
			return func() int {
				switch {
				case a.release == "" && b.release == "":
					return 0
				case a.release == "" && b.release != "":
					return -1
				case a.release != "" && b.release == "":
					return +1
				default:
					return 0
				}
			}()
		})
		return &max.severity, nil
	default:
		return nil, errors.Errorf("unexpected number of filtered severity annotations. expected: %d, actual: %d", []int{0, 1, 2}, len(filtered))
	}
}
