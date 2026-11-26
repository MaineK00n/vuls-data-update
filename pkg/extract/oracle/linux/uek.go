package linux

import (
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
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
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
// A UEK package is kernel-uek*, or a package whose fixed version is a UEK
// build: its release carries "uek" (e.g. "el9uek"), as bpftool, perf and
// python-perf built from the UEK source do. Its version part is taken as the
// series, so a UEK build with a version part of its own in the same advisory
// is reported as an error. The Red Hat compatible kernel (RHCK) ships some
// of these names too.
//
// Every UEK package is matched below its fixed version, and two conflicts
// are resolved once every advisory has been read, by uekIndex.apply:
//
//   - Between series, per CVE: a build of one series is compared with the
//     fix of a newer series for every CVE both list, even when its own
//     series fixed it. The newer series' advisory gives a CVE an older
//     series also fixed its own condition, whose UEK criterions leave out
//     the builds of that older series, per package and architecture; the
//     older series' own advisory matches them. A series without a fix of its
//     own keeps matching the newer fix: Oracle Linux OVAL only carries fixed
//     versions, so a missing fix cannot tell "not affected" from "not
//     fixed", and over-detection is preferred to missing the CVE.
//   - Between RHCK and UEK, per package and architecture: where a build
//     other than UEK (RHCK) of a UEK build's name is fixed on the same
//     release and architecture, the criterion of the UEK build starts at the
//     first build of its series, e.g. bpftool on Oracle Linux 8 and 9
//     [0:5.15.0-0, 0:5.15.0-305.176.4.el9uek), so that an RHCK build is not
//     compared with a UEK fix. The bound leaves out every older series for
//     every CVE, so such a package takes no part in the split. Elsewhere,
//     e.g. perf on Oracle Linux 7, which UEK ships for aarch64 and RHCK for
//     x86_64, the package is split as kernel-uek* is.

// uekSplitTagPrefix prefixes the detection tag of a split condition. The IDs
// of the older series' advisories whose series the condition leaves out
// follow, e.g. "kernel-uek-split:ELSA-2024-12868".
const uekSplitTagPrefix = "kernel-uek-split:"

// seriesBounds returns the bounds every build of a UEK series lies in,
// whatever its release: [<epoch>:<series>-0, <epoch>:<series>.0-0), e.g.
// [0:5.15.0-0, 0:5.15.0.0-0). rpm compares the version before the release,
// and of two versions equal in their common components the one with more
// components is the greater, so 5.15.0-<any release> < 5.15.0.0-0 < 5.15.1,
// 6.12.0.
func seriesBounds(epoch int, series string) (lower, upper string) {
	return fmt.Sprintf("%d:%s-0", epoch, series), fmt.Sprintf("%d:%s.0-0", epoch, series)
}

func isUEKKernelPackage(name string) bool {
	return strings.HasPrefix(name, "kernel-uek")
}

func isUEKBuild(version string) bool {
	rv := rpm.NewVersion(version)
	return strings.Contains(rv.Release(), "uek")
}

func isVersionCriterion(cn criterionTypes.Criterion) bool {
	return cn.Type == criterionTypes.CriterionTypeVersion && cn.Version != nil && cn.Version.Package.Binary != nil && cn.Version.Affected != nil
}

// isUEKCriterion reports whether cn is of a UEK package: kernel-uek*, or a
// UEK build.
func isUEKCriterion(cn criterionTypes.Criterion) bool {
	return isVersionCriterion(cn) && (isUEKKernelPackage(cn.Version.Package.Binary.Name) || slices.ContainsFunc(cn.Version.Affected.Fixed, isUEKBuild))
}

// uekIndex keeps what the split and the RHCK bound need of the advisories
// already written, so that only the ones to change are read back.
type uekIndex struct {
	roots []uekRoot
	paths map[string]struct{}
	// rhck holds, per ecosystem, the packages and architectures a build other
	// than UEK is fixed on; "" stands for every architecture.
	rhck map[ecosystemTypes.Ecosystem]map[uekPackage]struct{}
}

type uekRoot struct {
	id         dataTypes.RootID
	path       string
	raws       []string
	ecosystems map[ecosystemTypes.Ecosystem]uekEntry
}

// uekEntry is what an advisory carries of UEK packages in one ecosystem.
type uekEntry struct {
	series string
	fixed  map[uekPackage]string // the least fixed version per package and architecture
	cves   []vulnerabilityContentTypes.VulnerabilityID
}

type uekPackage struct {
	name string
	arch string
}

// uekSplit is what an advisory gets for the CVEs of one split tag in one
// ecosystem: the series its UEK criterions leave out.
type uekSplit struct {
	cves     map[vulnerabilityContentTypes.VulnerabilityID]struct{}
	excluded map[uekPackage]map[string]int // package and architecture -> older series -> epoch
}

func newUEKIndex() *uekIndex {
	return &uekIndex{
		paths: make(map[string]struct{}),
		rhck:  make(map[ecosystemTypes.Ecosystem]map[uekPackage]struct{}),
	}
}

func (x *uekIndex) add(path string, data dataTypes.Data) error {
	// The split and the bound rewrite the file once per advisory, so a second
	// definition with the same ID would be rewritten over the first.
	if _, ok := x.paths[path]; ok {
		return errors.Errorf("unexpected definitions of %s. expected: %q, actual: %q", data.ID, "one definition", "two or more")
	}
	x.paths[path] = struct{}{}

	root := uekRoot{
		id:         data.ID,
		path:       path,
		raws:       slices.Clone(data.DataSource.Raws),
		ecosystems: make(map[ecosystemTypes.Ecosystem]uekEntry),
	}

	for _, d := range data.Detections {
		e := uekEntry{fixed: make(map[uekPackage]string)}
		for _, cond := range d.Conditions {
			for _, cn := range cond.Criteria.Criterions {
				if !isVersionCriterion(cn) {
					continue
				}
				if !isUEKCriterion(cn) {
					if x.rhck[d.Ecosystem] == nil {
						x.rhck[d.Ecosystem] = make(map[uekPackage]struct{})
					}
					for _, a := range cn.Version.Package.Binary.Architectures {
						x.rhck[d.Ecosystem][uekPackage{name: cn.Version.Package.Binary.Name, arch: a}] = struct{}{}
					}
					continue
				}
				// The split and the bound are decided per package and architecture,
				// and every UEK criterion of Oracle Linux OVAL names its
				// architectures. A definition without an architecture test gives [""].
				if as := cn.Version.Package.Binary.Architectures; len(as) == 0 || slices.Contains(as, "") {
					return errors.Errorf("unexpected architectures of %s. ecosystem: %s, expected: %q, actual: %q", cn.Version.Package.Binary.Name, d.Ecosystem, "non-empty architectures", as)
				}
				for _, f := range cn.Version.Affected.Fixed {
					rv := rpm.NewVersion(f)
					switch s := rv.Version(); {
					case e.series == "":
						e.series = s
					case e.series != s:
						return errors.Errorf("unexpected UEK series in one advisory. ecosystem: %s, series: %q and %q", d.Ecosystem, e.series, s)
					}
					for _, a := range cn.Version.Package.Binary.Architectures {
						p := uekPackage{name: cn.Version.Package.Binary.Name, arch: a}
						if cur, ok := e.fixed[p]; !ok || rv.Compare(rpm.NewVersion(cur)) < 0 {
							e.fixed[p] = f
						}
					}
				}
			}
		}
		if len(e.fixed) == 0 {
			continue
		}

		for _, v := range data.Vulnerabilities {
			if slices.Contains(v.Segments, segmentTypes.Segment{Ecosystem: d.Ecosystem}) {
				e.cves = append(e.cves, v.Content.ID)
			}
		}

		root.ecosystems[d.Ecosystem] = e
	}

	if len(root.ecosystems) > 0 {
		x.roots = append(x.roots, root)
	}
	return nil
}

// bounded reports whether the criterion of a UEK build of p starts at the
// first build of its series: a build other than UEK (RHCK) of the name is
// fixed on the same release and architecture. kernel-uek* is never built
// from RHCK.
func (x *uekIndex) bounded(eco ecosystemTypes.Ecosystem, p uekPackage) bool {
	if isUEKKernelPackage(p.name) {
		return false
	}
	m := x.rhck[eco]
	if _, ok := m[p]; ok {
		return true
	}
	_, ok := m[uekPackage{name: p.name}]
	return ok
}

// apply gives, per Oracle Linux release, every advisory a split condition for
// the CVEs an older UEK series also fixed, and bounds the UEK builds of the
// names RHCK also ships (see bounded). The UEK criterions of a split
// condition match below the fixed version as before, except the builds of
// each older series that has its own fix for the CVE on the package and
// architecture, e.g. for a 6.12.0 fix of a CVE 5.15.0 also fixed:
// [ < 0:5.15.0-0 ] or [ >= 0:5.15.0.0-0, < 0:6.12.0-102.36.5.2.el9uek ).
// A build of the older series below its own fix is matched by the older
// series' own advisory, which carries the same package and architecture, so
// the fixed version reported for it is its own series'.
//
// Those CVEs move from the advisory's untagged condition to the split one;
// the other CVEs stay. CVEs whose left-out series come from the same older
// advisories get the same condition (see excluded), so they share one tag.
func (x *uekIndex) apply() error {
	byCVE := make(map[ecosystemTypes.Ecosystem]map[vulnerabilityContentTypes.VulnerabilityID][]int)
	for i, r := range x.roots {
		for eco, e := range r.ecosystems {
			if byCVE[eco] == nil {
				byCVE[eco] = make(map[vulnerabilityContentTypes.VulnerabilityID][]int)
			}
			for _, c := range e.cves {
				byCVE[eco][c] = append(byCVE[eco][c], i)
			}
		}
	}

	// root index -> ecosystem -> tag -> split
	splits := make(map[int]map[ecosystemTypes.Ecosystem]map[segmentTypes.DetectionTag]*uekSplit)
	raws := make(map[int][]string)
	for i, r := range x.roots {
		for eco, e := range r.ecosystems {
			for _, cve := range e.cves {
				excluded, from := x.excluded(eco, i, byCVE[eco][cve])
				if len(excluded) == 0 {
					continue
				}

				ids := make([]string, 0, len(from))
				for j := range from {
					ids = append(ids, string(x.roots[j].id))
					raws[i] = append(raws[i], x.roots[j].raws...)
				}
				slices.Sort(ids)
				tag := segmentTypes.DetectionTag(fmt.Sprintf("%s%s", uekSplitTagPrefix, strings.Join(ids, ",")))

				if splits[i] == nil {
					splits[i] = make(map[ecosystemTypes.Ecosystem]map[segmentTypes.DetectionTag]*uekSplit)
				}
				if splits[i][eco] == nil {
					splits[i][eco] = make(map[segmentTypes.DetectionTag]*uekSplit)
				}
				if splits[i][eco][tag] == nil {
					splits[i][eco][tag] = &uekSplit{cves: make(map[vulnerabilityContentTypes.VulnerabilityID]struct{}), excluded: excluded}
				}
				splits[i][eco][tag].cves[cve] = struct{}{}
			}
		}
	}

	for i, r := range x.roots {
		if len(splits[i]) == 0 && !x.hasBounded(r) {
			continue
		}
		if err := x.rewrite(r, splits[i], raws[i]); err != nil {
			return errors.Wrapf(err, "rewrite UEK conditions of %s", r.id)
		}
	}
	return nil
}

func (x *uekIndex) hasBounded(r uekRoot) bool {
	for eco, e := range r.ecosystems {
		for p := range e.fixed {
			if x.bounded(eco, p) {
				return true
			}
		}
	}
	return false
}

// excluded returns, for the advisory i among the advisories is listing a CVE
// in an ecosystem, the older series to leave out per package and architecture
// of i, each with the epoch of its fix, and the advisories they come from: an
// older series is left out on a package and architecture its own advisories
// for the CVE carry, unless the package is bounded, which leaves out every
// older series already.
//
// The result depends only on the advisories it comes from, since an
// advisory's packages are the same for all its CVEs: CVEs whose left-out
// series come from the same advisories get the same result.
func (x *uekIndex) excluded(eco ecosystemTypes.Ecosystem, i int, is []int) (map[uekPackage]map[string]int, map[int]struct{}) {
	e := x.roots[i].ecosystems[eco]
	sv := rpm.NewVersion(e.series)
	excluded := make(map[uekPackage]map[string]int)
	from := make(map[int]struct{})
	for _, j := range is {
		o := x.roots[j].ecosystems[eco]
		if rpm.NewVersion(o.series).Compare(sv) >= 0 {
			continue
		}
		for p := range e.fixed {
			if x.bounded(eco, p) {
				continue
			}
			f, ok := o.fixed[p]
			if !ok {
				continue
			}
			if excluded[p] == nil {
				excluded[p] = make(map[string]int)
			}
			rv := rpm.NewVersion(f)
			excluded[p][o.series] = rv.Epoch()
			from[j] = struct{}{}
		}
	}
	return excluded, from
}

func (x *uekIndex) rewrite(r uekRoot, splits map[ecosystemTypes.Ecosystem]map[segmentTypes.DetectionTag]*uekSplit, raws []string) error {
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

	for eco := range r.ecosystems {
		m := splits[eco]

		di := slices.IndexFunc(data.Detections, func(d detectionTypes.Detection) bool { return d.Ecosystem == eco })
		if di < 0 {
			return errors.Errorf("detection not found. ecosystem: %s", eco)
		}
		ci := slices.IndexFunc(data.Detections[di].Conditions, func(c conditionTypes.Condition) bool { return c.Tag == "" })
		if ci < 0 {
			return errors.Errorf("untagged condition not found. ecosystem: %s", eco)
		}
		base := data.Detections[di].Conditions[ci]
		untagged := segmentTypes.Segment{Ecosystem: eco}

		for tag, s := range m {
			cns, err := x.criterions(eco, base.Criteria.Criterions, s.excluded)
			if err != nil {
				return errors.Wrapf(err, "split criterions. ecosystem: %s", eco)
			}
			c := base.Criteria
			c.Criterions = cns
			data.Detections[di].Conditions = append(data.Detections[di].Conditions, conditionTypes.Condition{
				Criteria: c,
				Tag:      tag,
			})

			seg := segmentTypes.Segment{Ecosystem: eco, Tag: tag}
			for vi := range data.Vulnerabilities {
				if _, ok := s.cves[data.Vulnerabilities[vi].Content.ID]; ok {
					data.Vulnerabilities[vi].Segments = append(slices.DeleteFunc(data.Vulnerabilities[vi].Segments, func(x segmentTypes.Segment) bool { return x == untagged }), seg)
				}
			}
			for ai := range data.Advisories {
				data.Advisories[ai].Segments = append(data.Advisories[ai].Segments, seg)
			}
		}

		// The untagged condition gets the bound of RHCK alone.
		cns, err := x.criterions(eco, base.Criteria.Criterions, nil)
		if err != nil {
			return errors.Wrapf(err, "bound criterions. ecosystem: %s", eco)
		}
		data.Detections[di].Conditions[ci].Criteria.Criterions = cns

		// Drop the untagged condition once every CVE has moved to a split one.
		if len(m) > 0 && !slices.ContainsFunc(data.Vulnerabilities, func(v vulnerabilityTypes.Vulnerability) bool { return slices.Contains(v.Segments, untagged) }) {
			data.Detections[di].Conditions = slices.Delete(data.Detections[di].Conditions, ci, ci+1)
			for ai := range data.Advisories {
				data.Advisories[ai].Segments = slices.DeleteFunc(data.Advisories[ai].Segments, func(x segmentTypes.Segment) bool { return x == untagged })
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

// criterions copies cns, giving each UEK criterion its range per
// architecture: from the first build of its series if bounded, or else below
// the fixed version leaving out the builds of the older series in excluded.
// Architectures getting the same range share a criterion. The other
// criterions are copied as they are.
func (x *uekIndex) criterions(eco ecosystemTypes.Ecosystem, cns []criterionTypes.Criterion, excluded map[uekPackage]map[string]int) ([]criterionTypes.Criterion, error) {
	out := make([]criterionTypes.Criterion, 0, len(cns))
	for _, cn := range cns {
		if !isUEKCriterion(cn) {
			out = append(out, cn)
			continue
		}

		a := cn.Version.Affected
		if len(a.Fixed) != 1 || !slices.Equal(a.Range, []rangeTypes.Range{{LessThan: a.Fixed[0]}}) {
			return nil, errors.Errorf("unexpected affected of %s. expected: %q, actual: range %v, fixed %q", cn.Version.Package.Binary.Name, "range [{lt: <fixed>}] with one fixed", a.Range, a.Fixed)
		}
		fixed := a.Fixed[0]

		var (
			archs  [][]string
			ranges [][]rangeTypes.Range
		)
		for _, arch := range cn.Version.Package.Binary.Architectures {
			p := uekPackage{name: cn.Version.Package.Binary.Name, arch: arch}
			rs := func() []rangeTypes.Range {
				if x.bounded(eco, p) {
					rv := rpm.NewVersion(fixed)
					lower, _ := seriesBounds(rv.Epoch(), rv.Version())
					return []rangeTypes.Range{{GreaterEqual: lower, LessThan: fixed}}
				}
				return splitRange(fixed, excluded[p])
			}()
			if gi := slices.IndexFunc(ranges, func(r []rangeTypes.Range) bool { return slices.Equal(r, rs) }); gi >= 0 {
				archs[gi] = append(archs[gi], arch)
				continue
			}
			archs = append(archs, []string{arch})
			ranges = append(ranges, rs)
		}

		for gi, as := range archs {
			vc := *cn.Version
			b := *vc.Package.Binary
			b.Architectures = as
			vc.Package.Binary = &b
			vc.Affected = &affectedTypes.Affected{
				Type:  a.Type,
				Range: ranges[gi],
				Fixed: []string{fixed},
			}
			out = append(out, criterionTypes.Criterion{
				Type:    criterionTypes.CriterionTypeVersion,
				Version: &vc,
			})
		}
	}
	return out, nil
}

// splitRange returns the range below fixed leaving out every build of each
// older series (see seriesBounds), e.g.
// [ < 0:5.15.0-0 ] or [ >= 0:5.15.0.0-0, < 0:6.12.0-102.36.5.2.el9uek ).
func splitRange(fixed string, older map[string]int) []rangeTypes.Range {
	ss := slices.SortedFunc(maps.Keys(older), func(a, b string) int {
		return rpm.NewVersion(a).Compare(rpm.NewVersion(b))
	})

	rs := make([]rangeTypes.Range, 0, len(ss)+1)
	var lower string
	for _, s := range ss {
		lo, hi := seriesBounds(older[s], s)
		rs = append(rs, rangeTypes.Range{GreaterEqual: lower, LessThan: lo})
		lower = hi
	}
	return append(rs, rangeTypes.Range{GreaterEqual: lower, LessThan: fixed})
}
