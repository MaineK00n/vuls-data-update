package errata

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
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
	binaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/errata"
)

// Kernel builds of an older minor release that have their own minor's fix
//
// AlmaLinux builds the kernel of every minor release of a major from one
// version (5.14.0 on 9.x) and numbers the releases per minor: the first
// component of the release names the minor (9.6: 570, 9.7: 611, 9.8: 687,
// 9.9: 741), so every build of minor N lies in [E:V-N, E:V-(N+1)). A minor
// reaches its end of life when the next one is released, and a CVE fixed by a
// kernel advisory of one minor is often listed again by a kernel advisory of
// the next. All advisories of a major are written into one ecosystem with the
// range (-inf, fixed), so a kernel of the older minor that already has its own
// minor's fix is still below the newer minor's fixed version and is reported.
//
// excludeFixedOlderMinors takes those builds out, per CVE: in an advisory of
// minor M listing a CVE, a kernel package fixed at f on an architecture gets
// (-inf, f) minus [F_N, E:V-(N+1)) for every minor N < M, where F_N is the
// greatest fixed version of that package on that architecture among the
// advisories of minor N listing the CVE, and E:V are taken from F_N (bpftool
// has a version of its own). Where a minor has no such advisory (the 9.3
// kernel advisories are missing from the data) or its advisories lack the
// package or the architecture (AlmaLinux 10 keeps only the noarch packages of
// the kernel advisories of a superseded minor), there is no fix to go by and
// nothing is taken out.
//
// The holes differ by CVE, while a condition applies to every CVE of the
// advisory that carries its segment. So the CVEs with holes are grouped by
// their holes, each group gets a copy of the advisory's condition with the
// holes taken out of its kernel packages and a tag naming the releases of the
// fixes (see kernelHoleTagPrefix), and its CVEs carry the tag in place of the
// untagged segment. A CVE without holes keeps the untagged condition.

// kernelSRPMs are the source packages whose binaries follow that numbering.
// kernel-rt is a source package of its own on AlmaLinux 8 and 9.0-9.2, with
// the release numbers of the kernel of the same minor (e.g.
// 4.18.0-553.5.1.rt7.346.el8_10).
var kernelSRPMs = []string{"kernel", "kernel-rt"}

// kernelHoleTagPrefix prefixes the tag of a condition with holes. The releases
// of the fixes taken out follow, in ascending order, e.g.
// "kernel-fixed-in-older-minor:611.54.1.el9_7,687.59.1.el9_8". Where two
// groups of an advisory would get the same tag, "#<n>" is appended to each.
const kernelHoleTagPrefix = "kernel-fixed-in-older-minor:"

// kernelIndex keeps the kernel packages and the CVEs of the advisories
// written, so that only the advisories to change are read back.
type kernelIndex struct {
	advisories []kernelAdvisory
}

type kernelAdvisory struct {
	id        string
	path      string
	ecosystem ecosystemTypes.Ecosystem
	raws      []string
	cves      []vulnerabilityContentTypes.VulnerabilityID
	builds    []kernelBuild
}

// kernelBuild is a binary package of a kernel source package.
type kernelBuild struct {
	name    string
	arch    string
	epoch   string
	version string
	release string
	minor   int
}

// fixed returns the version as the criterion has it.
func (b kernelBuild) fixed() string {
	return fmt.Sprintf("%s:%s-%s", b.epoch, b.version, b.release)
}

// end returns the version above every build of b's minor: E:V-(N+1).
func (b kernelBuild) end() string {
	return fmt.Sprintf("%s:%s-%d", b.epoch, b.version, b.minor+1)
}

// hole is [from, to), the builds of a minor that have the minor's own fix.
type hole struct {
	minor   int
	release string
	from    string
	to      string
}

// criterionKey names a kernel package on an architecture in a criterion.
type criterionKey struct {
	name  string
	arch  string
	fixed string
}

func compareCriterionKey(x, y criterionKey) int {
	return cmp.Or(
		cmp.Compare(x.name, y.name),
		cmp.Compare(x.arch, y.arch),
		cmp.Compare(x.fixed, y.fixed),
	)
}

// kernelHoleGroup is the CVEs of an advisory with the same holes.
type kernelHoleGroup struct {
	tag   segmentTypes.DetectionTag
	holes map[criterionKey][]hole
	cves  []vulnerabilityContentTypes.VulnerabilityID
	raws  []string
}

// add records the kernel packages and the CVEs of an advisory written to path.
func (x *kernelIndex) add(path, osver string, fetched errata.Erratum, raws []string) {
	var builds []kernelBuild
	for _, p := range fetched.Packages {
		if p.Module != "" || !slices.Contains(kernelSRPMs, srpmName(p.Src)) {
			continue
		}
		minor, ok := minorOf(p.Release)
		if !ok {
			continue
		}
		b := kernelBuild{
			name:    p.Name,
			arch:    p.Arch,
			epoch:   p.Epoch,
			version: p.Version,
			release: p.Release,
			minor:   minor,
		}
		if !slices.Contains(builds, b) {
			builds = append(builds, b)
		}
	}
	if len(builds) == 0 {
		return
	}

	var cves []vulnerabilityContentTypes.VulnerabilityID
	for _, r := range fetched.References {
		if r.Type == "cve" && !slices.Contains(cves, vulnerabilityContentTypes.VulnerabilityID(r.ID)) {
			cves = append(cves, vulnerabilityContentTypes.VulnerabilityID(r.ID))
		}
	}
	if len(cves) == 0 {
		return
	}

	x.advisories = append(x.advisories, kernelAdvisory{
		id:        fetched.ID,
		path:      path,
		ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlma, osver)),
		raws:      raws,
		cves:      cves,
		builds:    builds,
	})
}

// srpmName returns the name of a source package from its file name, e.g.
// "kernel-rt" for "kernel-rt-4.18.0-553.5.1.rt7.346.el8_10.src.rpm".
func srpmName(filename string) string {
	nvr, ok := strings.CutSuffix(filename, ".src.rpm")
	if !ok {
		return ""
	}
	i := strings.LastIndex(nvr, "-")
	if i < 0 {
		return ""
	}
	j := strings.LastIndex(nvr[:i], "-")
	if j < 0 {
		return ""
	}
	return nvr[:j]
}

// minorOf returns the number of the minor release a kernel build belongs to:
// the first dot-separated component of its release, e.g. 687 for
// 687.59.1.el9_8. A release whose first component is not all digits gives
// false.
func minorOf(release string) (int, bool) {
	s, _, _ := strings.Cut(release, ".")
	if s == "" || strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' }) {
		return 0, false
	}
	// Only digits are left, so an error is an overflow, which no release
	// number reaches: such a release is left untouched like a non-numeric one.
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// excludeFixedOlderMinors takes the builds of older minors that have their own
// minor's fix out of the advisories written (see the comment at the top).
func (x *kernelIndex) excludeFixedOlderMinors() error {
	type ownKey struct {
		ecosystem ecosystemTypes.Ecosystem
		cve       vulnerabilityContentTypes.VulnerabilityID
		name      string
		arch      string
	}
	type ownFix struct {
		build kernelBuild
		raws  []string
	}

	// the fixes per minor, and the raws of the advisories they are taken from
	owns := make(map[ownKey]map[int]*ownFix)
	for _, a := range x.advisories {
		for _, c := range a.cves {
			for _, b := range a.builds {
				k := ownKey{ecosystem: a.ecosystem, cve: c, name: b.name, arch: b.arch}
				if owns[k] == nil {
					owns[k] = make(map[int]*ownFix)
				}
				o, ok := owns[k][b.minor]
				if !ok {
					owns[k][b.minor] = &ownFix{build: b, raws: slices.Clone(a.raws)}
					continue
				}
				if rpm.NewVersion(b.fixed()).Compare(rpm.NewVersion(o.build.fixed())) > 0 {
					o.build = b
				}
				o.raws = append(o.raws, a.raws...)
			}
		}
	}

	plans := make(map[string]map[ecosystemTypes.Ecosystem][]*kernelHoleGroup)
	for _, a := range x.advisories {
		groups := make(map[string]*kernelHoleGroup)
		for _, c := range a.cves {
			holes := make(map[criterionKey][]hole)
			var raws []string
			for _, b := range a.builds {
				fs := owns[ownKey{ecosystem: a.ecosystem, cve: c, name: b.name, arch: b.arch}]
				for _, n := range slices.Sorted(maps.Keys(fs)) {
					if n >= b.minor {
						break
					}
					k := criterionKey{name: b.name, arch: b.arch, fixed: b.fixed()}
					holes[k] = append(holes[k], hole{
						minor:   n,
						release: fs[n].build.release,
						from:    fs[n].build.fixed(),
						to:      fs[n].build.end(),
					})
					raws = append(raws, fs[n].raws...)
				}
			}
			if len(holes) == 0 {
				continue
			}

			for _, k := range slices.SortedFunc(maps.Keys(holes), compareCriterionKey) {
				if err := checkHoles(k.fixed, holes[k]); err != nil {
					return errors.Wrapf(err, "check holes. advisory: %s, ecosystem: %s, cve: %s, package: %s.%s", a.id, a.ecosystem, c, k.name, k.arch)
				}
			}

			key := holesKey(holes)
			g, ok := groups[key]
			if !ok {
				g = &kernelHoleGroup{holes: holes}
				groups[key] = g
			}
			g.cves = append(g.cves, c)
			g.raws = append(g.raws, raws...)
		}
		if len(groups) == 0 {
			continue
		}

		if plans[a.path] == nil {
			plans[a.path] = make(map[ecosystemTypes.Ecosystem][]*kernelHoleGroup)
		}
		if _, ok := plans[a.path][a.ecosystem]; ok {
			return errors.Errorf("unexpected advisory listed twice in an ecosystem. advisory: %s, ecosystem: %s", a.id, a.ecosystem)
		}
		plans[a.path][a.ecosystem] = tagHoleGroups(groups)
	}

	for _, p := range slices.Sorted(maps.Keys(plans)) {
		if err := punchHoles(p, plans[p]); err != nil {
			return errors.Wrapf(err, "punch holes in %s", p)
		}
	}
	return nil
}

// checkHoles checks that the holes, in ascending order of minor, are inside
// (-inf, fixed) and leave something between each other, so that the ranges
// around them are well ordered.
func checkHoles(fixed string, holes []hole) error {
	vs := make([]string, 0, 2*len(holes)+1)
	for _, h := range holes {
		vs = append(vs, h.from, h.to)
	}
	vs = append(vs, fixed)
	for i := 1; i < len(vs); i++ {
		if rpm.NewVersion(vs[i-1]).Compare(rpm.NewVersion(vs[i])) >= 0 {
			return errors.Errorf("unexpected order of versions. expected: %q, actual: %q", "strictly ascending", vs)
		}
	}
	return nil
}

// holesKey returns a string identifying the holes of a CVE in an advisory.
func holesKey(holes map[criterionKey][]hole) string {
	var b strings.Builder
	for _, k := range slices.SortedFunc(maps.Keys(holes), compareCriterionKey) {
		fmt.Fprintf(&b, "%s\x00%s\x00%s", k.name, k.arch, k.fixed)
		for _, h := range holes[k] {
			fmt.Fprintf(&b, "\x00%s\x00%s", h.from, h.to)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// tagHoleGroups names the groups of an advisory: kernelHoleTagPrefix and the
// releases of the fixes taken out, with "#<n>" appended in the order of their
// holes where groups would share a name. The groups are returned in the order
// of their names, so that what fails first does not depend on map order.
func tagHoleGroups(groups map[string]*kernelHoleGroup) []*kernelHoleGroup {
	byTag := make(map[string][]string)
	for key, g := range groups {
		hs := slices.Concat(slices.Collect(maps.Values(g.holes))...)
		slices.SortFunc(hs, func(x, y hole) int {
			return cmp.Or(
				cmp.Compare(x.minor, y.minor),
				rpm.NewVersion(x.release).Compare(rpm.NewVersion(y.release)),
				cmp.Compare(x.release, y.release),
			)
		})
		rs := make([]string, 0, len(hs))
		for _, h := range hs {
			rs = append(rs, h.release)
		}
		tag := fmt.Sprintf("%s%s", kernelHoleTagPrefix, strings.Join(slices.Compact(rs), ","))
		byTag[tag] = append(byTag[tag], key)
	}

	gs := make([]*kernelHoleGroup, 0, len(groups))
	for _, tag := range slices.Sorted(maps.Keys(byTag)) {
		keys := byTag[tag]
		if len(keys) == 1 {
			groups[keys[0]].tag = segmentTypes.DetectionTag(tag)
			gs = append(gs, groups[keys[0]])
			continue
		}
		slices.Sort(keys)
		for i, key := range keys {
			groups[key].tag = segmentTypes.DetectionTag(fmt.Sprintf("%s#%d", tag, i+1))
			gs = append(gs, groups[key])
		}
	}
	return gs
}

// punchHoles reads back the data written to path and gives each group of
// each ecosystem its condition.
func punchHoles(path string, plan map[ecosystemTypes.Ecosystem][]*kernelHoleGroup) error {
	data, err := func() (dataTypes.Data, error) {
		f, err := os.Open(path)
		if err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var data dataTypes.Data
		if err := json.UnmarshalRead(f, &data); err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "decode %s", path)
		}
		return data, nil
	}()
	if err != nil {
		return errors.Wrap(err, "read data")
	}

	for _, e := range slices.Sorted(maps.Keys(plan)) {
		if err := punchEcosystemHoles(&data, e, plan[e]); err != nil {
			return errors.Wrapf(err, "punch holes in %s", e)
		}
		for _, g := range plan[e] {
			for _, r := range g.raws {
				if !slices.Contains(data.DataSource.Raws, r) {
					data.DataSource.Raws = append(data.DataSource.Raws, r)
				}
			}
		}
	}

	if err := util.Write(path, data, true); err != nil {
		return errors.Wrapf(err, "write %s", path)
	}
	return nil
}

// punchEcosystemHoles adds the condition of each group to the detection of
// the ecosystem, and moves the group's CVEs to its tag. The untagged condition
// is dropped with the advisory's untagged segment once no CVE is left on it,
// since vuls reports an advisory matched through a segment none of its CVEs
// carries as a vulnerability of its own.
func punchEcosystemHoles(data *dataTypes.Data, ecosystem ecosystemTypes.Ecosystem, groups []*kernelHoleGroup) error {
	di := slices.IndexFunc(data.Detections, func(d detectionTypes.Detection) bool { return d.Ecosystem == ecosystem })
	if di < 0 {
		return errors.Errorf("detection not found. ecosystem: %s", ecosystem)
	}
	d := &data.Detections[di]

	var untagged []int
	for i, c := range d.Conditions {
		if c.Tag == "" {
			untagged = append(untagged, i)
		}
	}
	if len(untagged) != 1 {
		return errors.Errorf("unexpected number of untagged conditions. expected: %d, actual: %d", 1, len(untagged))
	}
	base := d.Conditions[untagged[0]].Criteria

	seg := segmentTypes.Segment{Ecosystem: ecosystem}
	for _, g := range groups {
		used := make(map[criterionKey]struct{}, len(g.holes))
		ca, err := g.criteria(base, used)
		if err != nil {
			return errors.Wrapf(err, "punch holes for %s", g.tag)
		}
		for _, k := range slices.SortedFunc(maps.Keys(g.holes), compareCriterionKey) {
			if _, ok := used[k]; !ok {
				return errors.Errorf("criterion not found. package: %s, arch: %s, fixed: %s", k.name, k.arch, k.fixed)
			}
		}
		d.Conditions = append(d.Conditions, conditionTypes.Condition{
			Criteria: ca,
			Tag:      g.tag,
		})

		tagged := segmentTypes.Segment{Ecosystem: ecosystem, Tag: g.tag}
		for _, c := range g.cves {
			n := 0
			for vi := range data.Vulnerabilities {
				if data.Vulnerabilities[vi].Content.ID != c {
					continue
				}
				if si := slices.Index(data.Vulnerabilities[vi].Segments, seg); si >= 0 {
					data.Vulnerabilities[vi].Segments[si] = tagged
					n++
				}
			}
			if n == 0 {
				return errors.Errorf("vulnerability not found. id: %s, ecosystem: %s", c, ecosystem)
			}
		}
		n := 0
		for ai := range data.Advisories {
			if slices.Contains(data.Advisories[ai].Segments, seg) {
				data.Advisories[ai].Segments = append(data.Advisories[ai].Segments, tagged)
				n++
			}
		}
		if n == 0 {
			return errors.Errorf("advisory not found. ecosystem: %s", ecosystem)
		}
	}

	if !slices.ContainsFunc(data.Vulnerabilities, func(v vulnerabilityTypes.Vulnerability) bool { return slices.Contains(v.Segments, seg) }) {
		d.Conditions = slices.Delete(d.Conditions, untagged[0], untagged[0]+1)
		for ai := range data.Advisories {
			data.Advisories[ai].Segments = slices.DeleteFunc(data.Advisories[ai].Segments, func(s segmentTypes.Segment) bool { return s == seg })
		}
	}

	return nil
}

// criteria returns a copy of ca with the holes taken out of its kernel
// packages, recording in used the packages found.
func (g kernelHoleGroup) criteria(ca criteriaTypes.Criteria, used map[criterionKey]struct{}) (criteriaTypes.Criteria, error) {
	c := criteriaTypes.Criteria{
		Operator:     ca.Operator,
		Repositories: slices.Clone(ca.Repositories),
	}
	if len(ca.Criterias) > 0 {
		c.Criterias = make([]criteriaTypes.Criteria, 0, len(ca.Criterias))
		for _, sub := range ca.Criterias {
			s, err := g.criteria(sub, used)
			if err != nil {
				return criteriaTypes.Criteria{}, errors.Wrap(err, "punch holes in criteria")
			}
			c.Criterias = append(c.Criterias, s)
		}
	}
	if len(ca.Criterions) > 0 {
		c.Criterions = make([]criterionTypes.Criterion, 0, len(ca.Criterions))
		for _, cn := range ca.Criterions {
			cns, err := g.criterions(cn, used)
			if err != nil {
				return criteriaTypes.Criteria{}, errors.Wrap(err, "punch holes in criterion")
			}
			c.Criterions = append(c.Criterions, cns...)
		}
	}
	return c, nil
}

// criterions returns cn with the holes taken out, split by architecture where
// the holes differ, or cn itself where it has none.
func (g kernelHoleGroup) criterions(cn criterionTypes.Criterion, used map[criterionKey]struct{}) ([]criterionTypes.Criterion, error) {
	if cn.Type != criterionTypes.CriterionTypeVersion || cn.Version == nil || cn.Version.Package.Binary == nil || cn.Version.Affected == nil || len(cn.Version.Affected.Fixed) != 1 {
		return []criterionTypes.Criterion{cn}, nil
	}
	name, fixed := cn.Version.Package.Binary.Name, cn.Version.Affected.Fixed[0]

	type split struct {
		holes  []hole
		arches []string
	}
	var splits []split
	for _, a := range cn.Version.Package.Binary.Architectures {
		k := criterionKey{name: name, arch: a, fixed: fixed}
		hs, ok := g.holes[k]
		if ok {
			used[k] = struct{}{}
		}
		i := slices.IndexFunc(splits, func(s split) bool { return slices.Equal(s.holes, hs) })
		if i < 0 {
			splits = append(splits, split{holes: hs})
			i = len(splits) - 1
		}
		splits[i].arches = append(splits[i].arches, a)
	}
	if !slices.ContainsFunc(splits, func(s split) bool { return len(s.holes) > 0 }) {
		return []criterionTypes.Criterion{cn}, nil
	}

	if want := []rangeTypes.Range{{LessThan: fixed}}; !slices.Equal(cn.Version.Affected.Range, want) {
		return nil, errors.Errorf("unexpected range of %s. expected: %+v, actual: %+v", name, want, cn.Version.Affected.Range)
	}

	cns := make([]criterionTypes.Criterion, 0, len(splits))
	for _, s := range splits {
		vc := *cn.Version
		vc.Package.Binary = &binaryPackageTypes.Package{
			Name:          name,
			Architectures: s.arches,
		}
		vc.Affected = &affectedTypes.Affected{
			Type:  cn.Version.Affected.Type,
			Range: punchedRanges(fixed, s.holes),
			Fixed: []string{fixed},
		}
		cns = append(cns, criterionTypes.Criterion{
			Type:    cn.Type,
			Version: &vc,
		})
	}
	return cns, nil
}

// punchedRanges returns (-inf, fixed) without the holes, given in ascending
// order: [{lt: from_1}, {ge: to_1, lt: from_2}, ..., {ge: to_k, lt: fixed}].
func punchedRanges(fixed string, holes []hole) []rangeTypes.Range {
	if len(holes) == 0 {
		return []rangeTypes.Range{{LessThan: fixed}}
	}

	rs := make([]rangeTypes.Range, 0, len(holes)+1)
	rs = append(rs, rangeTypes.Range{LessThan: holes[0].from})
	for i, h := range holes {
		lt := fixed
		if i+1 < len(holes) {
			lt = holes[i+1].from
		}
		rs = append(rs, rangeTypes.Range{GreaterEqual: h.to, LessThan: lt})
	}
	return rs
}
