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
// part names the series. The Red Hat compatible kernel (RHCK) ships bpftool,
// perf and python-perf under the same names as UEK.
//
// Two conflicts are resolved:
//
//   - Between RHCK and UEK, per package: fixedRange bounds the criterions of
//     the names RHCK also ships to the UEK series of their fixed version, so
//     that an RHCK build is not compared with a UEK fix.
//   - Between series, per CVE: a build of one series is compared with the
//     fix of a newer series for every CVE both list, even when its own
//     series fixed it. uekIndex.applySplit gives, in the newer series'
//     advisory, a CVE an older series also fixed its own condition, whose
//     kernel-uek* criterions leave out the builds of that older series, per
//     package and architecture; the older series' own advisory matches them.
//     A series without a fix of its own keeps matching the newer fix: Oracle
//     Linux OVAL only carries fixed versions, so a missing fix cannot tell
//     "not affected" from "not fixed", and over-detection is preferred to
//     missing the CVE.

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

// fixedRange returns the affected range for a fixed version of a package.
// For a name RHCK also ships, whose fixed version is a UEK build (its release
// carries "uek", e.g. "el9uek"), the range starts at the first build of the
// UEK series, which the version part names, e.g. bpftool
// [0:5.15.0-0, 0:5.15.0-305.176.4.el9uek). kernel-uek* is never built from
// RHCK, and its conflict between series is left to uekIndex.applySplit.
func fixedRange(name, fixed string) rangeTypes.Range {
	rv := rpm.NewVersion(fixed)
	if isUEKKernelPackage(name) || !strings.Contains(rv.Release(), "uek") {
		return rangeTypes.Range{LessThan: fixed}
	}
	lower, _ := seriesBounds(rv.Epoch(), rv.Version())
	return rangeTypes.Range{
		GreaterEqual: lower,
		LessThan:     fixed,
	}
}

func isUEKKernelPackage(name string) bool {
	return strings.HasPrefix(name, "kernel-uek")
}

func isUEKKernelCriterion(cn criterionTypes.Criterion) bool {
	return cn.Type == criterionTypes.CriterionTypeVersion && cn.Version != nil && cn.Version.Package.Binary != nil && cn.Version.Affected != nil && isUEKKernelPackage(cn.Version.Package.Binary.Name)
}

// uekIndex keeps what the split needs of the advisories already written, so
// that only the ones to change are read back.
type uekIndex struct {
	roots []uekRoot
}

type uekRoot struct {
	id         dataTypes.RootID
	path       string
	raws       []string
	ecosystems map[ecosystemTypes.Ecosystem]uekEntry
}

// uekEntry is what an advisory carries of kernel-uek* in one ecosystem.
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
// ecosystem: the series its kernel-uek* criterions leave out.
type uekSplit struct {
	cves     map[vulnerabilityContentTypes.VulnerabilityID]struct{}
	excluded map[uekPackage]map[string]int // package and architecture -> older series -> epoch
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
		e := uekEntry{fixed: make(map[uekPackage]string)}
		for _, cond := range d.Conditions {
			for _, cn := range cond.Criteria.Criterions {
				if !isUEKKernelCriterion(cn) {
					continue
				}
				// The split is decided per package and architecture, and every
				// kernel-uek* criterion of Oracle Linux OVAL names its architectures.
				// A definition without an architecture test gives [""].
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

// applySplit gives, per Oracle Linux release, every advisory a split
// condition for the CVEs an older UEK series also fixed. Its kernel-uek*
// criterions match below the fixed version as before, except the builds of
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
func (x *uekIndex) applySplit() error {
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

	for _, i := range slices.Sorted(maps.Keys(splits)) {
		if err := x.roots[i].rewrite(splits[i], raws[i]); err != nil {
			return errors.Wrapf(err, "split UEK conditions of %s", x.roots[i].id)
		}
	}
	return nil
}

// excluded returns, for the advisory i among the advisories is listing a CVE
// in an ecosystem, the older series to leave out per package and architecture
// of i, each with the epoch of its fix, and the advisories they come from: an
// older series is left out on a package and architecture its own advisories
// for the CVE carry.
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

func (r uekRoot) rewrite(splits map[ecosystemTypes.Ecosystem]map[segmentTypes.DetectionTag]*uekSplit, raws []string) error {
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

	for eco, m := range splits {
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
			cns, err := splitCriterions(base.Criteria.Criterions, s.excluded)
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

		// Drop the untagged condition once every CVE has moved to a split one.
		if !slices.ContainsFunc(data.Vulnerabilities, func(v vulnerabilityTypes.Vulnerability) bool { return slices.Contains(v.Segments, untagged) }) {
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

// splitCriterions copies cns, leaving out of each kernel-uek* criterion the
// builds of the older series in excluded, per architecture. Architectures
// getting the same range share a criterion. The other criterions are copied
// as they are.
func splitCriterions(cns []criterionTypes.Criterion, excluded map[uekPackage]map[string]int) ([]criterionTypes.Criterion, error) {
	out := make([]criterionTypes.Criterion, 0, len(cns))
	for _, cn := range cns {
		if !isUEKKernelCriterion(cn) {
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
			rs := splitRange(fixed, excluded[uekPackage{name: cn.Version.Package.Binary.Name, arch: arch}])
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
