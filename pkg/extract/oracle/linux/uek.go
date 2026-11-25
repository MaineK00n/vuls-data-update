package linux

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	rpm "github.com/knqyf263/go-rpm-version"
	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
)

// Unbreakable Enterprise Kernel (UEK)
//
// One Oracle Linux release ships several UEK series side by side (e.g.
// Oracle Linux 9: UEK R7 5.15.0 and UEK R8 6.12.0), and an ELSA is issued
// per series with the same package names. A series keeps its upstream
// version part fixed for its whole life and moves updates into the release
// (e.g. 5.15.0-0.30.19.el9uek ... 5.15.0-326.222.4.el9uek), so the version
// part names the series.
//
// Two things are done for them:
//
//   - fixedRange bounds every criterion whose fixed version is a UEK build
//     to its own series, so that a package of another series, or the
//     same-named package built from the Red Hat compatible kernel (bpftool,
//     perf), is not compared with it.
//   - uekIndex.applyFallback lets a kernel-uek* package of a series that has
//     no ELSA for a CVE fall back to the fixed version of another series:
//     Oracle Linux OVAL only carries fixed versions, so the missing ELSA
//     cannot tell "not affected" from "not fixed", and over-detection is
//     preferred to missing the CVE.

// uekFallbackTagPrefix prefixes the detection tag of a fallback condition.
// The series the condition is for follows, e.g. "kernel-uek-fallback:5.15.0".
const uekFallbackTagPrefix = "kernel-uek-fallback:"

// uekSeries returns the version part of v, which names the UEK series, when
// v is a UEK build (its release carries "uek", e.g. "el9uek").
func uekSeries(v string) (string, bool) {
	rv := rpm.NewVersion(v)
	if !strings.Contains(rv.Release(), "uek") {
		return "", false
	}
	return rv.Version(), true
}

// fixedRange returns the affected range for a fixed version. For a UEK build
// the range starts at the first build of its series, e.g.
// [0:5.15.0-0, 0:5.15.0-305.176.4.el9uek).
func fixedRange(fixed string) rangeTypes.Range {
	s, ok := uekSeries(fixed)
	if !ok {
		return rangeTypes.Range{LessThan: fixed}
	}
	rv := rpm.NewVersion(fixed)
	return rangeTypes.Range{
		GreaterEqual: fmt.Sprintf("%d:%s-0", rv.Epoch(), s),
		LessThan:     fixed,
	}
}

func isUEKKernelPackage(name string) bool {
	return strings.HasPrefix(name, "kernel-uek")
}

// uekIndex keeps what the fallback needs of the advisories already written,
// so that only the ones to change are read back.
type uekIndex struct {
	roots []uekRoot
}

type uekRoot struct {
	id         dataTypes.RootID
	path       string
	raws       []string
	ecosystems map[ecosystemTypes.Ecosystem]uekEntry
}

type uekEntry struct {
	series string
	fixed  string // the greatest fixed version of the kernel-uek* packages
	cves   []vulnerabilityContentTypes.VulnerabilityID
}

func newUEKIndex() *uekIndex {
	return &uekIndex{}
}

func (x *uekIndex) add(path string, data dataTypes.Data) error {
	root := uekRoot{
		id:         data.ID,
		path:       path,
		raws:       slices.Clone(data.DataSource.Raws),
		ecosystems: make(map[ecosystemTypes.Ecosystem]uekEntry),
	}

	for _, d := range data.Detections {
		var e uekEntry
		for _, cond := range d.Conditions {
			for _, cn := range cond.Criteria.Criterions {
				if cn.Type != criterionTypes.CriterionTypeVersion || cn.Version == nil || cn.Version.Package.Binary == nil || cn.Version.Affected == nil || !isUEKKernelPackage(cn.Version.Package.Binary.Name) {
					continue
				}
				for _, f := range cn.Version.Affected.Fixed {
					s, ok := uekSeries(f)
					if !ok {
						continue
					}
					switch {
					case e.series == "":
						e.series, e.fixed = s, f
					case e.series != s:
						return errors.Errorf("unexpected UEK series in one advisory. ecosystem: %s, series: %q and %q", d.Ecosystem, e.series, s)
					case rpm.NewVersion(f).Compare(rpm.NewVersion(e.fixed)) > 0:
						e.fixed = f
					}
				}
			}
		}
		if e.series == "" {
			continue
		}

		for _, v := range data.Vulnerabilities {
			if slices.Contains(v.Segments, segmentTypes.Segment{Ecosystem: d.Ecosystem}) {
				e.cves = append(e.cves, v.Content.ID)
			}
		}
		if len(e.cves) == 0 {
			continue
		}

		root.ecosystems[d.Ecosystem] = e
	}

	if len(root.ecosystems) > 0 {
		x.roots = append(x.roots, root)
	}
	return nil
}

// applyFallback adds, per Oracle Linux release and CVE, a fallback condition
// for every UEK series that has no ELSA for the CVE and is older than the
// newest series that has one. The condition is put in the advisory with the
// greatest fixed version for the CVE and carries that version, and only the
// CVEs it is for get its tag in their segments. A series newer than that
// version needs nothing, since its builds are never less than it.
func (x *uekIndex) applyFallback() error {
	series := make(map[ecosystemTypes.Ecosystem]map[string]struct{})
	byCVE := make(map[ecosystemTypes.Ecosystem]map[vulnerabilityContentTypes.VulnerabilityID][]int)
	for i, r := range x.roots {
		for eco, e := range r.ecosystems {
			if series[eco] == nil {
				series[eco] = make(map[string]struct{})
				byCVE[eco] = make(map[vulnerabilityContentTypes.VulnerabilityID][]int)
			}
			series[eco][e.series] = struct{}{}
			for _, c := range e.cves {
				byCVE[eco][c] = append(byCVE[eco][c], i)
			}
		}
	}

	// root index -> ecosystem -> fallback series -> CVEs
	plans := make(map[int]map[ecosystemTypes.Ecosystem]map[string][]vulnerabilityContentTypes.VulnerabilityID)
	raws := make(map[int][]string)
	for eco, m := range byCVE {
		for cve, is := range m {
			has := make(map[string]struct{}, len(is))
			best := is[0]
			for _, i := range is {
				has[x.roots[i].ecosystems[eco].series] = struct{}{}
				if x.compare(eco, i, best) > 0 {
					best = i
				}
			}

			bestSeries := x.roots[best].ecosystems[eco].series
			var targets []string
			for s := range series[eco] {
				if _, ok := has[s]; ok {
					continue
				}
				if rpm.NewVersion(s).Compare(rpm.NewVersion(bestSeries)) < 0 {
					targets = append(targets, s)
				}
			}
			if len(targets) == 0 {
				continue
			}

			if plans[best] == nil {
				plans[best] = make(map[ecosystemTypes.Ecosystem]map[string][]vulnerabilityContentTypes.VulnerabilityID)
			}
			if plans[best][eco] == nil {
				plans[best][eco] = make(map[string][]vulnerabilityContentTypes.VulnerabilityID)
			}
			for _, t := range targets {
				plans[best][eco][t] = append(plans[best][eco][t], cve)
			}
			for _, i := range is {
				if i != best {
					raws[best] = append(raws[best], x.roots[i].raws...)
				}
			}
		}
	}

	for _, i := range slices.Sorted(maps.Keys(plans)) {
		if err := x.roots[i].rewrite(plans[i], raws[i]); err != nil {
			return errors.Wrapf(err, "add UEK fallback to %s", x.roots[i].id)
		}
	}
	return nil
}

// compare orders two advisories for a CVE in an ecosystem by series, then by
// fixed version, then by ID.
func (x *uekIndex) compare(eco ecosystemTypes.Ecosystem, i, j int) int {
	a, b := x.roots[i].ecosystems[eco], x.roots[j].ecosystems[eco]
	return cmp.Or(
		rpm.NewVersion(a.series).Compare(rpm.NewVersion(b.series)),
		rpm.NewVersion(a.fixed).Compare(rpm.NewVersion(b.fixed)),
		cmp.Compare(x.roots[i].id, x.roots[j].id),
	)
}

func (r uekRoot) rewrite(plan map[ecosystemTypes.Ecosystem]map[string][]vulnerabilityContentTypes.VulnerabilityID, raws []string) error {
	data, err := func() (dataTypes.Data, error) {
		f, err := os.Open(r.path)
		if err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "open %s", r.path)
		}
		defer f.Close()

		var data dataTypes.Data
		if err := json.UnmarshalRead(f, &data); err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "decode %s", r.path)
		}
		return data, nil
	}()
	if err != nil {
		return errors.Wrap(err, "read data")
	}

	for eco, m := range plan {
		di := slices.IndexFunc(data.Detections, func(d detectionTypes.Detection) bool { return d.Ecosystem == eco })
		if di < 0 {
			return errors.Errorf("detection not found. ecosystem: %s", eco)
		}

		for target, cves := range m {
			cns := r.fallbackCriterions(data.Detections[di].Conditions, r.ecosystems[eco].series, target)
			if len(cns) == 0 {
				return errors.Errorf("no kernel-uek* criterion of series %s found. ecosystem: %s", r.ecosystems[eco].series, eco)
			}

			seg := segmentTypes.Segment{Ecosystem: eco, Tag: segmentTypes.DetectionTag(fmt.Sprintf("%s%s", uekFallbackTagPrefix, target))}

			data.Detections[di].Conditions = append(data.Detections[di].Conditions, conditionTypes.Condition{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: cns,
				},
				Tag: seg.Tag,
			})

			for vi := range data.Vulnerabilities {
				if slices.Contains(cves, data.Vulnerabilities[vi].Content.ID) {
					data.Vulnerabilities[vi].Segments = append(data.Vulnerabilities[vi].Segments, seg)
				}
			}
			for ai := range data.Advisories {
				data.Advisories[ai].Segments = append(data.Advisories[ai].Segments, seg)
			}
		}
	}

	data.DataSource.Raws = append(data.DataSource.Raws, raws...)
	slices.Sort(data.DataSource.Raws)
	data.DataSource.Raws = slices.Compact(data.DataSource.Raws)

	if err := util.Write(r.path, data, true); err != nil {
		return errors.Wrapf(err, "write %s", r.path)
	}
	return nil
}

// fallbackCriterions copies the kernel-uek* criterions of series out of the
// untagged conditions, matching the builds of the target series whatever
// their release, with the fixed version left as is.
func (r uekRoot) fallbackCriterions(conds []conditionTypes.Condition, series, target string) []criterionTypes.Criterion {
	var cns []criterionTypes.Criterion
	for _, cond := range conds {
		if cond.Tag != "" {
			continue
		}
		for _, cn := range cond.Criteria.Criterions {
			if cn.Type != criterionTypes.CriterionTypeVersion || cn.Version == nil || cn.Version.Package.Binary == nil || cn.Version.Affected == nil || !isUEKKernelPackage(cn.Version.Package.Binary.Name) {
				continue
			}
			if !slices.ContainsFunc(cn.Version.Affected.Fixed, func(f string) bool {
				s, ok := uekSeries(f)
				return ok && s == series
			}) {
				continue
			}

			vc := *cn.Version
			b := *vc.Package.Binary
			b.Architectures = slices.Clone(b.Architectures)
			vc.Package.Binary = &b
			vc.Affected = &affectedTypes.Affected{
				Type:  rangeTypes.RangeTypeRPMVersionOnly,
				Range: []rangeTypes.Range{{Equal: target}},
				Fixed: slices.Clone(cn.Version.Affected.Fixed),
			}
			cns = append(cns, criterionTypes.Criterion{
				Type:    criterionTypes.CriterionTypeVersion,
				Version: &vc,
			})
		}
	}
	return cns
}
