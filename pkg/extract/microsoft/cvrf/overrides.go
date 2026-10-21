package cvrf

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/pkg/errors"

	microsoftutil "github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/cvrf"
)

// overrideKind is the kind of correction a cvrfOverride makes.
type overrideKind int

const (
	// overrideExcludeVulnerability skips the vulnerability entry altogether.
	overrideExcludeVulnerability overrideKind = iota + 1
	// overrideRenameProduct takes product as renameTo, in the product info,
	// the detections and the KBs alike.
	overrideRenameProduct
	// overrideAddProduct lists product, which CVRF omits, as affected and fixed
	// in fixedBuild. It carries only the CVE-level data (title, description,
	// CWE, exploitability), never a severity or a CVSS Microsoft did not give.
	overrideAddProduct
	// overrideFixedBuild replaces the FixedBuild from of product's Vendor Fix
	// with fixedBuild. With from "", it also fixes product when CVRF lists it
	// without any Vendor Fix.
	overrideFixedBuild
	// overrideNoFixedBuild drops the FixedBuild from of product's Vendor Fix,
	// which gives no usable fixed build. The product stays fixed by the Vendor
	// Fix, through its KB if any. For a Microsoft Edge product, whose Vendor Fix
	// carries no KB, this acknowledges that the CVE yields no criterion (see
	// buildDetections).
	overrideNoFixedBuild
	// overrideExcludeVendorFix drops product's Vendor Fix kbID from the
	// detection. The product stays covered by it, and the KB stays collected.
	overrideExcludeVendorFix
	// overrideAddVendorFix adds a Vendor Fix (kbID, fixedBuild, hotpatch) to the
	// detection of product, which CVRF lists with a Vendor Fix of its own.
	overrideAddVendorFix
)

func (k overrideKind) String() string {
	switch k {
	case overrideExcludeVulnerability:
		return "overrideExcludeVulnerability"
	case overrideRenameProduct:
		return "overrideRenameProduct"
	case overrideAddProduct:
		return "overrideAddProduct"
	case overrideFixedBuild:
		return "overrideFixedBuild"
	case overrideNoFixedBuild:
		return "overrideNoFixedBuild"
	case overrideExcludeVendorFix:
		return "overrideExcludeVendorFix"
	case overrideAddVendorFix:
		return "overrideAddVendorFix"
	default:
		return fmt.Sprintf("overrideKind(%d)", int(k))
	}
}

// cvrfOverride corrects the CVRF data of one vulnerability entry, cve, for a
// known data issue. product is the product name as CVRF lists it, after any
// overrideRenameProduct of the same entry.
type cvrfOverride struct {
	cve        string
	kind       overrideKind
	product    string
	renameTo   string
	from       string
	fixedBuild string
	kbID       string
	hotpatch   bool
}

func (o cvrfOverride) String() string {
	s := fmt.Sprintf("%s %s", o.cve, o.kind)
	if o.product != "" {
		s += fmt.Sprintf(" product %q", o.product)
	}
	switch o.kind {
	case overrideRenameProduct:
		s += fmt.Sprintf(" to %q", o.renameTo)
	case overrideAddProduct:
		s += fmt.Sprintf(" fixed build %q", o.fixedBuild)
	case overrideFixedBuild:
		s += fmt.Sprintf(" from %q to %q", o.from, o.fixedBuild)
	case overrideNoFixedBuild:
		s += fmt.Sprintf(" from %q", o.from)
	case overrideExcludeVendorFix:
		s += fmt.Sprintf(" KB %q", o.kbID)
	case overrideAddVendorFix:
		s += fmt.Sprintf(" KB %q fixed build %q hotpatch %t", o.kbID, o.fixedBuild, o.hotpatch)
	default:
	}
	return s
}

// validate checks that o carries the fields its kind needs and no other, so
// that a typo cannot make it silently miss or do something else.
func (o cvrfOverride) validate() error {
	if !strings.HasPrefix(o.cve, "CVE-") && !strings.HasPrefix(o.cve, "ADV") {
		return errors.Errorf("unexpected entry ID. expected: %q, actual: %q", []string{"CVE-*", "ADV*"}, o.cve)
	}

	type field struct {
		name string
		set  bool
	}
	fields := []field{
		{"product", o.product != ""},
		{"renameTo", o.renameTo != ""},
		{"from", o.from != ""},
		{"fixedBuild", o.fixedBuild != ""},
		{"kbID", o.kbID != ""},
		{"hotpatch", o.hotpatch},
	}
	var required, allowed []string
	switch o.kind {
	case overrideExcludeVulnerability:
	case overrideRenameProduct:
		required = []string{"product", "renameTo"}
	case overrideAddProduct:
		required = []string{"product", "fixedBuild"}
	case overrideFixedBuild:
		required, allowed = []string{"product", "fixedBuild"}, []string{"from"}
	case overrideNoFixedBuild:
		required, allowed = []string{"product"}, []string{"from"}
	case overrideExcludeVendorFix:
		required = []string{"product", "kbID"}
	case overrideAddVendorFix:
		required, allowed = []string{"product"}, []string{"kbID", "fixedBuild", "hotpatch"}
	default:
		return errors.Errorf("unexpected override kind. expected: %q, actual: %q", []overrideKind{overrideExcludeVulnerability, overrideRenameProduct, overrideAddProduct, overrideFixedBuild, overrideNoFixedBuild, overrideExcludeVendorFix, overrideAddVendorFix}, o.kind)
	}
	for _, f := range fields {
		switch {
		case slices.Contains(required, f.name) && !f.set:
			return errors.Errorf("unexpected %s. expected: %s set, actual: unset", o.kind, f.name)
		case !slices.Contains(required, f.name) && !slices.Contains(allowed, f.name) && f.set:
			return errors.Errorf("unexpected %s. expected: %s unset, actual: set", o.kind, f.name)
		}
	}

	switch o.kind {
	case overrideRenameProduct:
		if o.renameTo == o.product {
			return errors.Errorf("unexpected %s. expected: a different name, actual: %q", o.kind, o.renameTo)
		}
	case overrideFixedBuild:
		if o.fixedBuild == o.from {
			return errors.Errorf("unexpected %s. expected: a different fixed build, actual: %q", o.kind, o.fixedBuild)
		}
	case overrideAddVendorFix:
		if o.kbID == "" && o.fixedBuild == "" {
			return errors.Errorf("unexpected %s. expected: a KB ID or a fixed build, actual: neither", o.kind)
		}
	default:
	}
	if o.kbID != "" && !isAllDigits(o.kbID) {
		return errors.Errorf("unexpected KB ID. expected: digits only, actual: %q", o.kbID)
	}
	if o.fixedBuild != "" {
		if _, err := buildFixedBuildCriterion(o.cve, microsoftutil.NormalizeProductName(o.product), o.fixedBuild); err != nil {
			return errors.Wrapf(err, "build fixed build criterion")
		}
		if o.fixedBuild != cleanFixedBuild(o.fixedBuild) {
			return errors.Errorf("unexpected fixed build. expected: %q, actual: %q", cleanFixedBuild(o.fixedBuild), o.fixedBuild)
		}
	}
	return nil
}

// cvrfOverrideIndex maps a vulnerability entry to the indexes of its
// cvrfOverrides.
var cvrfOverrideIndex = func() map[string][]int {
	m := make(map[string][]int)
	for i, o := range cvrfOverrides {
		m[o.cve] = append(m[o.cve], i)
	}
	return m
}()

// overrideUsage records which cvrfOverrides took effect, so that one that no
// longer does, typically because Microsoft corrected the data since, fails the
// extraction instead of lingering unnoticed.
type overrideUsage struct {
	seen map[string]struct{}
	used map[int]struct{}
}

func newOverrideUsage() *overrideUsage {
	return &overrideUsage{
		seen: make(map[string]struct{}),
		used: make(map[int]struct{}),
	}
}

func (u *overrideUsage) see(cve string) {
	u.seen[cve] = struct{}{}
}

func (u *overrideUsage) use(i int) {
	u.used[i] = struct{}{}
}

// unused returns the overrides of the vulnerability entries seen that took
// effect nowhere. An entry the input does not contain is not checked, as an
// extraction of a subset of the documents cannot tell.
func (u *overrideUsage) unused() []string {
	var ss []string
	for i, o := range cvrfOverrides {
		if _, ok := u.seen[o.cve]; !ok {
			continue
		}
		if _, ok := u.used[i]; ok {
			continue
		}
		ss = append(ss, o.String())
	}
	return ss
}

// overriddenVulnerability is a vulnerability entry with the overrides that
// correct its CVRF data applied: overrideRenameProduct, overrideAddProduct,
// overrideFixedBuild and overrideNoFixedBuild. Every extraction step reads it.
// overrideExcludeVendorFix and overrideAddVendorFix are applied by
// buildDetections only: they reshape how the fixes of a product combine, which
// the KBs collected from CVRF do not follow.
type overriddenVulnerability struct {
	v cvrf.Vulnerability
	// products maps a product ID to its name.
	products map[string]string
	// noFixedBuild holds the indexes in v.Remediations.Remediation of the
	// Vendor Fixes whose FixedBuild overrideNoFixedBuild dropped.
	noFixedBuild map[int]struct{}
	usage        *overrideUsage
}

// applyOverrides applies the overrides of v.CVE that correct its CVRF data.
// v and products are never modified.
func applyOverrides(v cvrf.Vulnerability, products map[string]string, u *overrideUsage) overriddenVulnerability {
	o := overriddenVulnerability{v: v, products: products, usage: u}
	idxs := cvrfOverrideIndex[v.CVE]
	if len(idxs) == 0 {
		return o
	}

	o.products = maps.Clone(products)
	o.v.ProductStatuses.Status.ProductID = slices.Clone(v.ProductStatuses.Status.ProductID)
	rs := slices.Clone(v.Remediations.Remediation)
	noFixedBuild := make([]bool, len(rs))

	listed := func(product string) []string {
		var pids []string
		for _, pid := range o.v.ProductStatuses.Status.ProductID {
			if o.products[pid] == product {
				pids = append(pids, pid)
			}
		}
		return pids
	}

	pinned := false
	for _, kind := range []overrideKind{overrideRenameProduct, overrideAddProduct, overrideFixedBuild, overrideNoFixedBuild} {
		for _, i := range idxs {
			ov := cvrfOverrides[i]
			if ov.kind != kind {
				continue
			}
			switch kind {
			case overrideRenameProduct:
				for pid, name := range o.products {
					if name == ov.product {
						o.products[pid] = ov.renameTo
						u.use(i)
					}
				}
			case overrideAddProduct:
				if len(listed(ov.product)) > 0 {
					// CVRF lists the product now: the override no longer
					// takes effect and is reported as unused.
					continue
				}
				if !pinned {
					// A Mitigation or Workaround without ProductID applies to
					// every product of the entry. Pin it to the products CVRF
					// lists, as it does not cover one Microsoft did not list.
					for ri, r := range rs {
						if len(r.ProductID) == 0 && (r.Type == "Mitigation" || r.Type == "Workaround") {
							rs[ri].ProductID = slices.Clone(o.v.ProductStatuses.Status.ProductID)
						}
					}
					pinned = true
				}
				pid := fmt.Sprintf("override:%s", ov.product)
				o.products[pid] = ov.product
				o.v.ProductStatuses.Status.ProductID = append(o.v.ProductStatuses.Status.ProductID, pid)
				rs = appendZero(rs)
				rs[len(rs)-1].Type = "Vendor Fix"
				rs[len(rs)-1].ProductID = []string{pid}
				rs[len(rs)-1].FixedBuild = ov.fixedBuild
				noFixedBuild = append(noFixedBuild, false)
				u.use(i)
			case overrideFixedBuild, overrideNoFixedBuild:
				fixedBuild := ov.fixedBuild
				if kind == overrideNoFixedBuild {
					fixedBuild = ""
				}
				covered := make(map[string]struct{})
				for ri := 0; ri < len(rs); ri++ {
					r := rs[ri]
					if r.Type != "Vendor Fix" {
						continue
					}
					var match, rest []string
					for _, pid := range r.ProductID {
						if o.products[pid] == ov.product {
							match = append(match, pid)
							covered[pid] = struct{}{}
						} else {
							rest = append(rest, pid)
						}
					}
					if len(match) == 0 || cleanFixedBuild(r.FixedBuild) != ov.from {
						continue
					}
					if len(rest) == 0 {
						rs[ri].FixedBuild = fixedBuild
						noFixedBuild[ri] = kind == overrideNoFixedBuild
					} else {
						// The remediation also fixes other products: split this
						// product off into a remediation of its own.
						rs[ri].ProductID = rest
						nr := r
						nr.ProductID = match
						nr.FixedBuild = fixedBuild
						rs = slices.Insert(rs, ri+1, nr)
						noFixedBuild = slices.Insert(noFixedBuild, ri+1, kind == overrideNoFixedBuild)
						ri++
					}
					u.use(i)
				}
				if kind == overrideFixedBuild && ov.from == "" {
					// A product CVRF lists without any Vendor Fix.
					for _, pid := range listed(ov.product) {
						if _, ok := covered[pid]; ok {
							continue
						}
						rs = appendZero(rs)
						rs[len(rs)-1].Type = "Vendor Fix"
						rs[len(rs)-1].ProductID = []string{pid}
						rs[len(rs)-1].FixedBuild = fixedBuild
						noFixedBuild = append(noFixedBuild, false)
						u.use(i)
					}
				}
			default:
			}
		}
	}

	o.v.Remediations.Remediation = rs
	for ri, b := range noFixedBuild {
		if !b {
			continue
		}
		if o.noFixedBuild == nil {
			o.noFixedBuild = make(map[int]struct{})
		}
		o.noFixedBuild[ri] = struct{}{}
	}
	return o
}

// appendZero appends the zero value to s, for the anonymous element types of
// the CVRF document.
func appendZero[S ~[]E, E any](s S) S {
	var zero E
	return append(s, zero)
}

// excluded reports whether the entry's overrideExcludeVulnerability skips it.
func (u *overrideUsage) excluded(cve string) bool {
	u.see(cve)
	for _, i := range cvrfOverrideIndex[cve] {
		if cvrfOverrides[i].kind == overrideExcludeVulnerability {
			u.use(i)
			return true
		}
	}
	return false
}

// vendorFixExcluded reports whether an overrideExcludeVendorFix drops the
// Vendor Fix kbID of product from the detection.
func (o overriddenVulnerability) vendorFixExcluded(product, kbID string) bool {
	for _, i := range cvrfOverrideIndex[o.v.CVE] {
		ov := cvrfOverrides[i]
		if ov.kind == overrideExcludeVendorFix && ov.product == product && ov.kbID == kbID {
			o.usage.use(i)
			return true
		}
	}
	return false
}

// addedVendorFixes returns the overrideAddVendorFix of the entry by product,
// and the products in order.
func (o overriddenVulnerability) addedVendorFixes() ([]string, map[string][]int) {
	m := make(map[string][]int)
	for _, i := range cvrfOverrideIndex[o.v.CVE] {
		if cvrfOverrides[i].kind == overrideAddVendorFix {
			m[cvrfOverrides[i].product] = append(m[cvrfOverrides[i].product], i)
		}
	}
	return slices.SortedFunc(maps.Keys(m), cmp.Compare), m
}

// errUnusedOverrides formats the overrides that took effect nowhere.
func errUnusedOverrides(unused []string) error {
	slices.Sort(unused)
	return errors.Errorf("unexpected cvrfOverrides that no longer take effect. expected: each override changes the CVRF data of its entry, actual: %q, please check whether Microsoft corrected the data and remove or update them", unused)
}

// cvrfOverrides corrects known data issues in CVRF, one entry per correction.
// Every override must take effect: one that no longer changes the data of its
// entry fails the extraction (see overrideUsage).
var cvrfOverrides = []cvrfOverride{
	// overrideExcludeVulnerability: entries Microsoft published that must not be
	// extracted, malformed or explicitly deprecated ones whose ID is not a
	// usable CVE identifier. The advisory text of these flags them as unusable
	// (e.g. a duplicate placeholder titled "... do not use this one"), so
	// extracting them would surface a bogus, uncorrelatable vulnerability ID.
	// They contribute neither data nor KB aggregation.
	{cve: "CVE-2023-38039 mariner - do not use this one", kind: overrideExcludeVulnerability},
	// "-M" duplicates: Microsoft re-published these open-source component CVEs
	// — already extracted under their canonical CVE IDs — with a CBL-Mariner /
	// Azure Linux-only product set and a malformed "-M" ID. After the
	// CBL-Mariner / Azure Linux product skip they yield zero detection
	// segments, so keeping them only adds a bogus, uncorrelatable CVE ID.
	{cve: "CVE-2022-2601-M", kind: overrideExcludeVulnerability},
	{cve: "CVE-2022-3775-M", kind: overrideExcludeVulnerability},
	{cve: "CVE-2023-32002 - M", kind: overrideExcludeVulnerability},
	{cve: "CVE-2024-0132-M", kind: overrideExcludeVulnerability},

	// overrideRenameProduct: entries that attribute the fix to the wrong
	// product.
	// CVE-2025-47967 — Microsoft Edge (Chromium-based) for Android Spoofing
	// Vulnerability (2025-Sep). The title, the description and the FAQ version
	// table (140.0.3485.71, released only for Android per the Edge security
	// release notes, Sep 16, 2025) all name Edge for Android, but CVRF lists
	// Microsoft Edge (Chromium-based), whose Stable channel never shipped
	// 140.0.3485.71 (140.0.3485.66 on Sep 11, 140.0.3485.81 on Sep 19).
	{cve: "CVE-2025-47967", kind: overrideRenameProduct, product: "Microsoft Edge (Chromium-based)", renameTo: "Microsoft Edge for Android"},

	// overrideAddProduct: products Microsoft omitted from an entry's
	// ProductTree / ProductStatuses / Remediations altogether, but which are
	// documented elsewhere (e.g. the Edge security release notes) to be
	// affected and fixed in the given build. When the product IS listed but its
	// FixedBuild is wrong or empty, use overrideFixedBuild instead.
	// CVE-2023-21796 — Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability
	// CVRF lists only "Microsoft Edge (Chromium-based) Extended Stable" (PID 12142,
	// fixed at 108.0.1462.83); the Stable channel is absent from ProductTree /
	// ProductStatuses / Remediations entirely, even though the same fix ships in
	// the Stable channel per Microsoft Edge Stable Release Notes (Jan 12, 2023),
	// which credit CVE-2023-21796 to 109.0.1518.49.
	// https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
	{cve: "CVE-2023-21796", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based)", fixedBuild: "109.0.1518.49"},
	// CVE-2026-66323 / CVE-2026-66324 — Microsoft Edge (Chromium-based) Remote Code
	// Execution / Spoofing Vulnerability (2026-Aug). CVRF lists only the platform
	// products (Microsoft Edge for Windows/MAC/Linux/Android/iOS) in ProductStatuses /
	// Remediations, unlike the other Microsoft-CNA Edge CVEs of the same release, while
	// the Microsoft Edge Stable Release Notes (Aug 27, 2026) credit both to 152.0.4191.53.
	// https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
	{cve: "CVE-2026-66323", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based)", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66324", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based)", fixedBuild: "152.0.4191.53"},
	// Microsoft Edge (Chromium-based) Extended Stable: CVRF lists only the Stable product, while the
	// CVE FAQ version table also gives the Extended Stable release. Each value matches the Edge branch
	// of its major version, and the Edge security release notes where they list the CVE. Exceptions:
	//   - 2023-Jul: the FAQ has the typo 114.0.1901.183; Extended Stable shipped 114.0.1823.90 (Jul 21, 2023)
	//   - CVE-2023-4863: the release notes credit 116.0.1938.81 (Sep 12, 2023), the FAQ the later 116.0.1938.98
	//   - CVE-2024-21388: the release notes credit 120.0.2210.160 (Jan 26, 2024), the FAQ also lists 120.0.2210.167
	{cve: "CVE-2022-3075", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "104.0.1293.81"},
	{cve: "CVE-2022-3723", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "106.0.1370.61"},
	{cve: "CVE-2022-3885", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "106.0.1370.72"},
	{cve: "CVE-2022-3886", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "106.0.1370.72"},
	{cve: "CVE-2022-3887", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "106.0.1370.72"},
	{cve: "CVE-2022-3888", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "106.0.1370.72"},
	{cve: "CVE-2022-3889", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "106.0.1370.72"},
	{cve: "CVE-2022-3890", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "106.0.1370.72"},
	{cve: "CVE-2022-4135", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "106.0.1370.86"},
	{cve: "CVE-2023-1213", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1219", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1221", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1222", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1223", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1224", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1229", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1230", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1231", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1233", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1234", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1235", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1236", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1530", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.78"},
	{cve: "CVE-2023-1531", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.78"},
	{cve: "CVE-2023-1533", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "110.0.1587.78"},
	{cve: "CVE-2023-2459", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-2460", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-2462", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-2463", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-2464", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-2465", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-2466", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-2467", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-2468", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-3727", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-3732", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-3733", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-3734", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-3735", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-3736", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-3737", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-3738", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-3740", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-4863", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "116.0.1938.81"},
	{cve: "CVE-2023-5186", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "116.0.1938.98"},
	{cve: "CVE-2023-5187", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "116.0.1938.98"},
	{cve: "CVE-2023-5217", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "116.0.1938.98"},
	{cve: "CVE-2023-6345", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "118.0.2088.122"},
	{cve: "CVE-2023-6346", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "118.0.2088.122"},
	{cve: "CVE-2023-6347", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "118.0.2088.122"},
	{cve: "CVE-2023-6348", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "118.0.2088.122"},
	{cve: "CVE-2023-6350", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "118.0.2088.122"},
	{cve: "CVE-2023-6351", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "118.0.2088.122"},
	{cve: "CVE-2023-29350", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-29354", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "112.0.1722.71"},
	{cve: "CVE-2023-35392", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-36014", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "118.0.2088.102"},
	{cve: "CVE-2023-38187", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2024-0804", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0805", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0806", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0807", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0808", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0809", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0810", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0811", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0812", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0813", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-0814", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-1059", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.167"},
	{cve: "CVE-2024-1060", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.167"},
	{cve: "CVE-2024-1077", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.167"},
	{cve: "CVE-2024-2400", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "122.0.2365.92"},
	{cve: "CVE-2024-5830", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5831", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5832", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5833", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5834", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5835", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5836", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5837", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5838", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5839", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5840", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5841", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5842", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5843", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5844", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5845", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5846", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-5847", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},
	{cve: "CVE-2024-9120", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "128.0.2739.97"},
	{cve: "CVE-2024-21326", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-21336", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-21382", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-21383", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-21385", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-21388", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.160"},
	{cve: "CVE-2024-21399", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "120.0.2210.167"},
	{cve: "CVE-2024-30058", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.56"},

	// Microsoft Edge (Chromium-based) Extended Stable, where the CVE FAQ gives a single version but
	// the Edge security release notes credit the fix to an Extended Stable release as well (date of
	// that release)
	{cve: "CVE-2023-29345", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.37"},  // Jun 2, 2023
	{cve: "CVE-2023-33143", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.37"},  // Jun 2, 2023
	{cve: "CVE-2023-33145", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.51"},  // Jun 15, 2023
	{cve: "CVE-2023-36887", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.82"},  // Jul 13, 2023
	{cve: "CVE-2023-38157", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "114.0.1823.106"}, // Aug 7, 2023
	{cve: "CVE-2023-38158", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "116.0.1938.54"},  // Aug 21, 2023
	{cve: "CVE-2023-36787", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "116.0.1938.54"},  // Aug 21, 2023
	{cve: "CVE-2024-4761", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "124.0.2478.105"},  // May 14, 2024
	{cve: "CVE-2024-4947", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "124.0.2478.109"},  // May 16, 2024
	{cve: "CVE-2024-30056", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "124.0.2478.109"}, // May 16, 2024
	{cve: "CVE-2024-5274", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "124.0.2478.127"},  // May 24, 2024
	{cve: "CVE-2024-38218", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.137"}, // Aug 8, 2024
	{cve: "CVE-2024-38219", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "126.0.2592.137"}, // Aug 8, 2024
	{cve: "CVE-2024-38221", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "128.0.2739.90"},  // Sep 19, 2024
	{cve: "CVE-2024-43489", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "128.0.2739.90"},  // Sep 19, 2024
	{cve: "CVE-2024-43496", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "128.0.2739.90"},  // Sep 19, 2024
	{cve: "CVE-2025-21279", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "132.0.2957.171"}, // Feb 20, 2025
	{cve: "CVE-2025-21283", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "132.0.2957.171"}, // Feb 20, 2025
	{cve: "CVE-2025-21342", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "132.0.2957.171"}, // Feb 20, 2025
	{cve: "CVE-2025-21408", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "132.0.2957.171"}, // Feb 20, 2025
	{cve: "CVE-2025-5419", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "136.0.3240.115"},  // Jun 4, 2025
	{cve: "CVE-2026-2441", kind: overrideAddProduct, product: "Microsoft Edge (Chromium-based) Extended Stable", fixedBuild: "144.0.3719.130"},  // Feb 17, 2026

	// Microsoft Edge for Android / iOS: CVRF lists only Microsoft Edge (Chromium-based), while the
	// Edge security release notes also credit the fix to the Android and iOS releases
	// CVE-2026-40416: 148.0.3967.55 (May 11, 2026)
	{cve: "CVE-2026-40416", kind: overrideAddProduct, product: "Microsoft Edge for Android", fixedBuild: "148.0.3967.55"},
	{cve: "CVE-2026-40416", kind: overrideAddProduct, product: "Microsoft Edge for iOS", fixedBuild: "148.0.3967.55"},
	// CVE-2026-41107: 148.0.3967.55 (May 11, 2026)
	{cve: "CVE-2026-41107", kind: overrideAddProduct, product: "Microsoft Edge for Android", fixedBuild: "148.0.3967.55"},
	{cve: "CVE-2026-41107", kind: overrideAddProduct, product: "Microsoft Edge for iOS", fixedBuild: "148.0.3967.55"},
	// CVE-2026-42838: 148.0.3967.55 (May 11, 2026)
	{cve: "CVE-2026-42838", kind: overrideAddProduct, product: "Microsoft Edge for Android", fixedBuild: "148.0.3967.55"},
	{cve: "CVE-2026-42838", kind: overrideAddProduct, product: "Microsoft Edge for iOS", fixedBuild: "148.0.3967.55"},
	// CVE-2026-45495: 148.0.3967.70 (Android May 21, iOS May 19, 2026)
	{cve: "CVE-2026-45495", kind: overrideAddProduct, product: "Microsoft Edge for Android", fixedBuild: "148.0.3967.70"},
	{cve: "CVE-2026-45495", kind: overrideAddProduct, product: "Microsoft Edge for iOS", fixedBuild: "148.0.3967.70"},
	// CVE-2026-72970: 151.0.4129.86 (Aug 17, 2026)
	{cve: "CVE-2026-72970", kind: overrideAddProduct, product: "Microsoft Edge for Android", fixedBuild: "151.0.4129.86"},
	{cve: "CVE-2026-72970", kind: overrideAddProduct, product: "Microsoft Edge for iOS", fixedBuild: "151.0.4129.86"},

	// overrideFixedBuild / overrideNoFixedBuild: FixedBuild values CVRF gets
	// wrong, keyed by the FixedBuild after the generic cleanup (cleanFixedBuild).
	// overrideNoFixedBuild acknowledges the upstream data gap and skips the
	// criterion. For Microsoft Edge, a Vendor Fix that yields no criterion and
	// has neither fails the extraction (see buildDetections), because such CVEs
	// would otherwise become silently undetectable.
	// .NET Core / .NET 5+ (FixedBuild has pre-release suffix that the parser doesn't accept)
	// 2021-May (FixedBuild "5.0.6-servicing.21220.11" / "3.1.15-servicing.21214.3" has pre-release suffix)
	{cve: "CVE-2021-31204", kind: overrideFixedBuild, product: ".NET 5.0", from: "5.0.6-servicing.21220.11", fixedBuild: "5.0.6"},
	{cve: "CVE-2021-31204", kind: overrideFixedBuild, product: ".NET Core 3.1", from: "3.1.15-servicing.21214.3", fixedBuild: "3.1.15"},

	// Microsoft Defender for Endpoint for Linux (FixedBuild is 4-part, parser expects 3-part)
	// 2026-Feb (CVE-2026-21537, FixedBuild "1.0.9.0" has extra revision segment)
	{cve: "CVE-2026-21537", kind: overrideFixedBuild, product: "Microsoft Defender for Endpoint for Linux", from: "1.0.9.0", fixedBuild: "1.0.9"},

	// Microsoft Edge (Chromium-based)
	// 2020-May (Edge 83)
	{cve: "CVE-2020-1195", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "83.0.478.37"},
	// 2020-Jul (Edge 84)
	{cve: "CVE-2020-1341", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "84.0.522.40"},
	// 2020-Sep (Edge 85)
	{cve: "CVE-2020-16884", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "85.0.564.44"},
	// 2021-Jan (Edge 88.0.705.50)
	{cve: "CVE-2020-16044", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21118", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21119", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21120", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21121", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21122", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21123", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21124", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21125", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21126", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21127", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21128", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21129", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21130", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21131", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21132", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21133", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21134", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21135", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21136", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21137", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21139", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21140", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	{cve: "CVE-2021-21141", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.50"},
	// 2021-Feb (Edge 88.0.705.62, 88.0.705.63, 88.0.705.74)
	{cve: "CVE-2021-21142", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.62"},
	{cve: "CVE-2021-21143", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.62"},
	{cve: "CVE-2021-21144", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.62"},
	{cve: "CVE-2021-21145", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.62"},
	{cve: "CVE-2021-21146", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.62"},
	{cve: "CVE-2021-21147", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.62"},
	{cve: "CVE-2021-24113", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.62"},
	{cve: "CVE-2021-21148", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.63"},
	{cve: "CVE-2021-21149", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.74"},
	{cve: "CVE-2021-21150", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.74"},
	{cve: "CVE-2021-21151", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.74"},
	{cve: "CVE-2021-21152", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.74"},
	{cve: "CVE-2021-21153", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.74"},
	{cve: "CVE-2021-21154", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.74"},
	{cve: "CVE-2021-21155", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.74"},
	{cve: "CVE-2021-21156", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.74"},
	{cve: "CVE-2021-21157", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "88.0.705.74"},
	// 2021-Mar (Edge 89.0.774.45, 89.0.774.54)
	// 2021-Apr (Edge 89.0.774.68, 89.0.774.77, 90.0.818.39, 90.0.818.46, 90.0.818.51)
	{cve: "CVE-2021-21194", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "89.0.774.68"},
	{cve: "CVE-2021-21195", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "89.0.774.68"},
	{cve: "CVE-2021-21196", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "89.0.774.68"},
	{cve: "CVE-2021-21197", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "89.0.774.68"},
	{cve: "CVE-2021-21198", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "89.0.774.68"},
	{cve: "CVE-2021-21199", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "89.0.774.68"},
	{cve: "CVE-2021-21206", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "89.0.774.77"},
	{cve: "CVE-2021-21220", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "89.0.774.77"},
	{cve: "CVE-2021-21201", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21202", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21203", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21204", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21205", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21207", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21208", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21209", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21210", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21211", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21212", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21213", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21214", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21215", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21216", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21217", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21218", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21219", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21221", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.39"},
	{cve: "CVE-2021-21222", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.46"},
	{cve: "CVE-2021-21223", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.46"},
	// CVE-2021-21224 (exploited in the wild) shipped in 90.0.818.41 per the Edge security release
	// notes (Apr 16, 2021); the FAQ version table gives the later 90.0.818.46 with a 4/15/2021 date
	{cve: "CVE-2021-21224", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.41"},
	{cve: "CVE-2021-21225", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.46"},
	{cve: "CVE-2021-21226", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.46"},
	{cve: "CVE-2021-21227", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.51"},
	{cve: "CVE-2021-21228", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.51"},
	{cve: "CVE-2021-21229", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.51"},
	{cve: "CVE-2021-21230", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.51"},
	{cve: "CVE-2021-21231", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.51"},
	{cve: "CVE-2021-21232", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.51"},
	{cve: "CVE-2021-21233", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.51"},
	// 2021-May (Edge 90.0.818.62)
	{cve: "CVE-2021-30506", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30507", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30508", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30509", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30510", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30511", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30512", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30513", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30514", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30515", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30516", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30517", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30518", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30519", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	{cve: "CVE-2021-30520", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "90.0.818.62"},
	// 2021-Jun (Edge 91.0.864.48)
	{cve: "CVE-2021-30544", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	{cve: "CVE-2021-30545", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	{cve: "CVE-2021-30546", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	{cve: "CVE-2021-30547", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	{cve: "CVE-2021-30548", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	{cve: "CVE-2021-30549", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	{cve: "CVE-2021-30550", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	{cve: "CVE-2021-30551", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	{cve: "CVE-2021-30552", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	{cve: "CVE-2021-30553", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "91.0.864.48"},
	// 2021-Nov (Edge 96.0.1054.29, FixedBuild has typo "96.0 1954.29"; the FAQ version table
	// repeats it as 96.0.1954.29, but the Edge 96 branch is 1054 per the Edge security release
	// notes, Nov 19, 2021)
	{cve: "CVE-2021-38005", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38006", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38007", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38008", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38009", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38010", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38011", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38012", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38013", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38014", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38015", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38016", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38017", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38018", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38019", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38020", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38021", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-38022", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-42308", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-43220", kind: overrideFixedBuild, product: "Microsoft Edge for iOS", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	{cve: "CVE-2021-43221", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "96.0 1954.29", fixedBuild: "96.0.1054.29"},
	// 2023-Feb (Edge 109.0.1518.78, FixedBuild has typo "109.0.15.18.78")
	{cve: "CVE-2023-21720", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "109.0.15.18.78", fixedBuild: "109.0.1518.78"},
	// 2023-Apr (Edge 112.0.1722.34, FixedBuild has Chromium version "112.0.5615.49/50" instead of Edge version)
	{cve: "CVE-2023-1810", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1811", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1812", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1813", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1814", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1815", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1816", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1817", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1818", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1819", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1820", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1821", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1822", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-1823", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-24935", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	{cve: "CVE-2023-28301", kind: overrideFixedBuild, product: "Microsoft Edge for Android", from: "112.0.5615.49/50", fixedBuild: "112.0.1722.34"},
	// 2025-May (Edge 136.0.3240.64, FixedBuild has "v" prefix "v136.0.3240.64")
	{cve: "CVE-2025-4372", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "v136.0.3240.64", fixedBuild: "136.0.3240.64"},
	// 2026-Mar (Edge 145.0.3800.99, FixedBuild "145.3800.99" has only 3 segments instead of 4)
	{cve: "CVE-2026-3537", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "145.3800.99", fixedBuild: "145.0.3800.99"},
	// 2026-Jul (Chromium 150 batch CVEs published without FixedBuild; mapped to the
	// Edge 150 security releases via the NVD Chrome fixed versions, cross-checked
	// against sibling entries in the same CVRF document that do carry FixedBuild:
	// Chrome 150.0.7871.46/47 -> Edge 150.0.4078.48, Chrome 150.0.7871.125 -> Edge 150.0.4078.80)
	{cve: "CVE-2026-13918", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-13973", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-13989", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14006", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14016", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14027", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14034", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14035", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14036", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14037", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14038", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14039", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14040", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14041", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14042", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14043", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14044", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14045", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14046", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14047", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14048", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14049", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14050", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14051", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14052", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14053", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14054", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14055", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14056", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14057", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14058", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14059", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14060", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14061", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14062", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14063", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14064", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14065", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14068", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14069", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14070", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14071", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14072", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14073", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14074", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14076", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14077", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14078", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14079", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14080", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14081", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14082", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14083", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14084", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14085", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14086", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14087", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14088", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14089", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14090", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14091", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14092", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14093", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14094", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14095", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14097", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14105", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14116", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14130", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14142", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14153", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-14397", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.48"},
	{cve: "CVE-2026-15764", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.80"},
	{cve: "CVE-2026-15765", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.80"},
	{cve: "CVE-2026-15766", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.80"},
	{cve: "CVE-2026-15768", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.80"},
	{cve: "CVE-2026-15769", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.80"},
	{cve: "CVE-2026-15770", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.80"},
	// CVE-2026-57990 carries no Remediations at all, so it reaches the
	// ProductStatuses fallback instead of the Vendor Fix guard; its FAQ version
	// table gives 150.0.4078.99 (07/24/2026, Chromium 150.0.7871.187), matching
	// the FixedBuild carried by CVE-2026-57978/57989 in the same document
	{cve: "CVE-2026-57990", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "150.0.4078.99"},
	// 2026-Aug (Edge 152, Microsoft-CNA CVEs): FixedBuild "152.0.4191.52" matches no
	// release; the FAQ version table and the Edge security release notes (Aug 27, 2026)
	// give 152.0.4191.53, as does CVE-2026-72984's own Chromium-based Vendor Fix.
	// CVE-2026-58616/62904/66798 list Chromium-based as Known Affected but attach the
	// Vendor Fix only to the platform products, so it reaches the ProductStatuses fallback
	{cve: "CVE-2026-58616", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-58616", kind: overrideFixedBuild, product: "Microsoft Edge for Linux", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-58616", kind: overrideFixedBuild, product: "Microsoft Edge for MAC", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-58616", kind: overrideFixedBuild, product: "Microsoft Edge for Windows", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-62904", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-62904", kind: overrideFixedBuild, product: "Microsoft Edge for Linux", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-62904", kind: overrideFixedBuild, product: "Microsoft Edge for MAC", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-62904", kind: overrideFixedBuild, product: "Microsoft Edge for Windows", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66323", kind: overrideFixedBuild, product: "Microsoft Edge for Linux", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66323", kind: overrideFixedBuild, product: "Microsoft Edge for MAC", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66323", kind: overrideFixedBuild, product: "Microsoft Edge for Windows", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66324", kind: overrideFixedBuild, product: "Microsoft Edge for Linux", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66324", kind: overrideFixedBuild, product: "Microsoft Edge for MAC", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66324", kind: overrideFixedBuild, product: "Microsoft Edge for Windows", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66798", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66798", kind: overrideFixedBuild, product: "Microsoft Edge for Linux", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66798", kind: overrideFixedBuild, product: "Microsoft Edge for MAC", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66798", kind: overrideFixedBuild, product: "Microsoft Edge for Windows", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-70341", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-70341", kind: overrideFixedBuild, product: "Microsoft Edge for Linux", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-70341", kind: overrideFixedBuild, product: "Microsoft Edge for MAC", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-72984", kind: overrideFixedBuild, product: "Microsoft Edge for Linux", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-72984", kind: overrideFixedBuild, product: "Microsoft Edge for MAC", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-72984", kind: overrideFixedBuild, product: "Microsoft Edge for Windows", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	// 2026-Aug Android/iOS: FixedBuild "152.0.4191.52" matches no release either; the Edge security
	// release notes (Aug 31, 2026) give 152.0.4191.53 for Microsoft Edge for Android and iOS
	{cve: "CVE-2026-58616", kind: overrideFixedBuild, product: "Microsoft Edge for Android", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-58616", kind: overrideFixedBuild, product: "Microsoft Edge for iOS", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-62904", kind: overrideFixedBuild, product: "Microsoft Edge for Android", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-62904", kind: overrideFixedBuild, product: "Microsoft Edge for iOS", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66323", kind: overrideFixedBuild, product: "Microsoft Edge for Android", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66323", kind: overrideFixedBuild, product: "Microsoft Edge for iOS", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66324", kind: overrideFixedBuild, product: "Microsoft Edge for Android", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66324", kind: overrideFixedBuild, product: "Microsoft Edge for iOS", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66798", kind: overrideFixedBuild, product: "Microsoft Edge for Android", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-66798", kind: overrideFixedBuild, product: "Microsoft Edge for iOS", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-70341", kind: overrideFixedBuild, product: "Microsoft Edge for Android", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-70341", kind: overrideFixedBuild, product: "Microsoft Edge for iOS", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-72984", kind: overrideFixedBuild, product: "Microsoft Edge for Android", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},
	{cve: "CVE-2026-72984", kind: overrideFixedBuild, product: "Microsoft Edge for iOS", from: "152.0.4191.52", fixedBuild: "152.0.4191.53"},

	// Stable FixedBuild corrections against the Edge security release notes
	// (https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security), each
	// agreeing with the CVE FAQ version table unless noted.
	// 2021-Sep: FixedBuild is the Chromium version (93.0.4577.82); Edge shipped 93.0.961.47 (Sep 11, 2021)
	{cve: "CVE-2021-30632", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "93.0.4577.82", fixedBuild: "93.0.961.47"},
	// 2022-Apr: exploited in the wild, fixed in 100.0.1185.44 (Apr 15, 2022), not the earlier 100.0.1185.29
	{cve: "CVE-2022-1364", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "100.0.1185.29", fixedBuild: "100.0.1185.44"},
	// 2023-Sep: FixedBuild is the Extended Stable version; Stable shipped 117.0.2045.47 (Sep 29, 2023).
	// The Extended Stable fix (116.0.1938.98) comes from an overrideAddProduct
	{cve: "CVE-2023-5186", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "116.0.1938.98", fixedBuild: "117.0.2045.47"},
	{cve: "CVE-2023-5187", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "116.0.1938.98", fixedBuild: "117.0.2045.47"},
	{cve: "CVE-2023-5217", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "116.0.1938.98", fixedBuild: "117.0.2045.47"},
	// 2024-Feb: 121.0.2277.113 matches no release; Stable shipped 121.0.2277.112 (Feb 8, 2024)
	{cve: "CVE-2024-1283", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "121.0.2277.113", fixedBuild: "121.0.2277.112"},
	{cve: "CVE-2024-1284", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "121.0.2277.113", fixedBuild: "121.0.2277.112"},
	// 2024-Jan: the release notes credit CVE-2024-21388 to 121.0.2277.83 (Jan 26, 2024); the FAQ also
	// carries a second table for the Feb 1 release (121.0.2277.98), which the FixedBuild took
	{cve: "CVE-2024-21388", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "121.0.2277.98", fixedBuild: "121.0.2277.83"},
	// 2024-Jun: FixedBuild "126.0.2592.8" is truncated; Stable shipped 126.0.2592.81 (Jun 27, 2024)
	{cve: "CVE-2024-34122", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "126.0.2592.8", fixedBuild: "126.0.2592.81"},
	{cve: "CVE-2024-6290", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "126.0.2592.8", fixedBuild: "126.0.2592.81"},
	{cve: "CVE-2024-6291", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "126.0.2592.8", fixedBuild: "126.0.2592.81"},
	{cve: "CVE-2024-6292", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "126.0.2592.8", fixedBuild: "126.0.2592.81"},
	{cve: "CVE-2024-6293", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "126.0.2592.8", fixedBuild: "126.0.2592.81"},
	// 2025-Apr: Stable shipped the fix in 135.0.3179.73 (Apr 11, 2025), not 134.0.3124.93
	{cve: "CVE-2025-29834", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "134.0.3124.93", fixedBuild: "135.0.3179.73"},
	// 2026-May: FixedBuild is the Android/iOS version (148.0.3967.55, May 11, 2026); Stable shipped
	// 148.0.3967.54 (May 7, 2026). The Android/iOS fix comes from an overrideAddProduct
	{cve: "CVE-2026-40416", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "148.0.3967.55", fixedBuild: "148.0.3967.54"},
	{cve: "CVE-2026-41107", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "148.0.3967.55", fixedBuild: "148.0.3967.54"},
	{cve: "CVE-2026-42838", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "148.0.3967.55", fixedBuild: "148.0.3967.54"},
	// 2026-Sep: Stable shipped the fix in 152.0.4191.66 (Sep 4, 2026), not 153.0.4234.32
	{cve: "CVE-2026-87491", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based)", from: "153.0.4234.32", fixedBuild: "152.0.4191.66"},

	// Microsoft Edge (Chromium-based) Extended Stable FixedBuild corrections, against the CVE FAQ
	// version table and the Edge security release notes
	// 2023-Mar: FixedBuild is the Chromium version; Extended Stable shipped 110.0.1587.69 (Mar 13, 2023)
	{cve: "CVE-2023-1214", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "110.0.5481.192", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1215", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "110.0.5481.192", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1216", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "110.0.5481.192", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1217", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "110.0.5481.192", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1220", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "110.0.5481.192", fixedBuild: "110.0.1587.69"},
	{cve: "CVE-2023-1228", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "110.0.5481.192", fixedBuild: "110.0.1587.69"},
	// 2023-Jul: FixedBuild is the Stable version (the FAQ has the typo 114.0.1901.183); Extended
	// Stable shipped 114.0.1823.90 (Jul 21, 2023)
	{cve: "CVE-2023-3728", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "115.0.1901.183", fixedBuild: "114.0.1823.90"},
	{cve: "CVE-2023-3730", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "115.0.1901.183", fixedBuild: "114.0.1823.90"},
	// 2024-Mar: FixedBuild is the Chromium version; Extended Stable shipped 122.0.2365.113 (Mar 27, 2024)
	{cve: "CVE-2024-2883", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "122.0.6261.148", fixedBuild: "122.0.2365.113"},
	{cve: "CVE-2024-2885", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "122.0.6261.148", fixedBuild: "122.0.2365.113"},
	{cve: "CVE-2024-2886", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "122.0.6261.148", fixedBuild: "122.0.2365.113"},
	{cve: "CVE-2024-2887", kind: overrideFixedBuild, product: "Microsoft Edge (Chromium-based) Extended Stable", from: "122.0.6261.148", fixedBuild: "122.0.2365.113"},

	// Microsoft Edge for Android / iOS
	// 2026-Mar: FixedBuild "145.3800.99" drops the minor version (the release notes repeat it, Mar 9, 2026)
	{cve: "CVE-2026-26133", kind: overrideFixedBuild, product: "Microsoft Edge for Android", from: "145.3800.99", fixedBuild: "145.0.3800.99"},
	{cve: "CVE-2026-26133", kind: overrideFixedBuild, product: "Microsoft Edge for iOS", from: "145.3800.99", fixedBuild: "145.0.3800.99"},

	// Microsoft Exchange Server
	// 2021-Mar (CVE-2021-26855 / 26857 / 26858 / 27065, the HAFNIUM CVEs): three Exchange Server 2019
	// FixedBuild values are wrong upstream. CU1 carries a 15.1-series value that matches no Exchange
	// 2019 build at all, and CU4 and CU6 have their values swapped. Left as-is, CU1 and CU6 never
	// satisfy LessThan (false negative) and a patched CU4 always does (false positive). Corrected
	// against the Mar21SU rows of https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates
	{cve: "CVE-2021-26855", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 1", from: "15.01.1979.006", fixedBuild: "15.02.0330.011"},
	{cve: "CVE-2021-26855", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 4", from: "15.02.0659.012", fixedBuild: "15.02.0529.013"},
	{cve: "CVE-2021-26855", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 6", from: "15.02.0529.013", fixedBuild: "15.02.0659.012"},
	{cve: "CVE-2021-26857", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 1", from: "15.01.1979.006", fixedBuild: "15.02.0330.011"},
	{cve: "CVE-2021-26857", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 4", from: "15.02.0659.012", fixedBuild: "15.02.0529.013"},
	{cve: "CVE-2021-26857", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 6", from: "15.02.0529.013", fixedBuild: "15.02.0659.012"},
	{cve: "CVE-2021-26858", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 1", from: "15.01.1979.006", fixedBuild: "15.02.0330.011"},
	{cve: "CVE-2021-26858", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 4", from: "15.02.0659.012", fixedBuild: "15.02.0529.013"},
	{cve: "CVE-2021-26858", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 6", from: "15.02.0529.013", fixedBuild: "15.02.0659.012"},
	{cve: "CVE-2021-27065", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 1", from: "15.01.1979.006", fixedBuild: "15.02.0330.011"},
	{cve: "CVE-2021-27065", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 4", from: "15.02.0659.012", fixedBuild: "15.02.0529.013"},
	{cve: "CVE-2021-27065", kind: overrideFixedBuild, product: "Microsoft Exchange Server 2019 Cumulative Update 6", from: "15.02.0529.013", fixedBuild: "15.02.0659.012"},

	// Microsoft Office / Excel / Office Online Server / Office Web Apps Server
	// 2021-Sep (FixedBuild "5381.1000" / "5215.1000" / "10378.20000" missing "15.0." or "16.0." prefix)
	{cve: "CVE-2021-38646", kind: overrideFixedBuild, product: "Microsoft Office 2013 RT Service Pack 1", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38646", kind: overrideFixedBuild, product: "Microsoft Office 2013 Service Pack 1 (32-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38646", kind: overrideFixedBuild, product: "Microsoft Office 2013 Service Pack 1 (64-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38650", kind: overrideFixedBuild, product: "Microsoft Office 2013 RT Service Pack 1", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38650", kind: overrideFixedBuild, product: "Microsoft Office 2013 Service Pack 1 (32-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38650", kind: overrideFixedBuild, product: "Microsoft Office 2013 Service Pack 1 (64-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38658", kind: overrideFixedBuild, product: "Microsoft Office 2013 RT Service Pack 1", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38658", kind: overrideFixedBuild, product: "Microsoft Office 2013 Service Pack 1 (32-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38658", kind: overrideFixedBuild, product: "Microsoft Office 2013 Service Pack 1 (64-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38658", kind: overrideFixedBuild, product: "Microsoft Office 2016 (32-bit edition)", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38658", kind: overrideFixedBuild, product: "Microsoft Office 2016 (64-bit edition)", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38646", kind: overrideFixedBuild, product: "Microsoft Office 2016 (32-bit edition)", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38646", kind: overrideFixedBuild, product: "Microsoft Office 2016 (64-bit edition)", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38650", kind: overrideFixedBuild, product: "Microsoft Office 2016 (32-bit edition)", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38650", kind: overrideFixedBuild, product: "Microsoft Office 2016 (64-bit edition)", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38655", kind: overrideFixedBuild, product: "Microsoft Excel 2013 RT Service Pack 1", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38655", kind: overrideFixedBuild, product: "Microsoft Excel 2013 Service Pack 1 (32-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38655", kind: overrideFixedBuild, product: "Microsoft Excel 2013 Service Pack 1 (64-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38660", kind: overrideFixedBuild, product: "Microsoft Excel 2013 RT Service Pack 1", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38660", kind: overrideFixedBuild, product: "Microsoft Excel 2013 Service Pack 1 (32-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38660", kind: overrideFixedBuild, product: "Microsoft Excel 2013 Service Pack 1 (64-bit editions)", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38655", kind: overrideFixedBuild, product: "Microsoft Excel 2016 (32-bit edition)", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38655", kind: overrideFixedBuild, product: "Microsoft Excel 2016 (64-bit edition)", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38655", kind: overrideFixedBuild, product: "Microsoft Office Online Server", from: "10378.20000", fixedBuild: "16.0.10378.20000"},
	{cve: "CVE-2021-38655", kind: overrideFixedBuild, product: "Microsoft Office Web Apps Server 2013 Service Pack 1", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	// 2021-Jul (Office 2019 for Mac, FixedBuild "16.51.210711.01" has extra dot in build segment, should be "16.51.21071101")
	{cve: "CVE-2021-34501", kind: overrideFixedBuild, product: "Microsoft Office 2019 for Mac", from: "16.51.210711.01", fixedBuild: "16.51.21071101"},

	// Microsoft SharePoint
	// 2021-Sep (FixedBuild "5381.1000" / "5215.1000" / "10378.20002" missing "15.0." or "16.0." prefix)
	{cve: "CVE-2021-38651", kind: overrideFixedBuild, product: "Microsoft SharePoint Foundation 2013 Service Pack 1", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38652", kind: overrideFixedBuild, product: "Microsoft SharePoint Foundation 2013 Service Pack 1", from: "5381.1000", fixedBuild: "15.0.5381.1000"},
	{cve: "CVE-2021-38651", kind: overrideFixedBuild, product: "Microsoft SharePoint Enterprise Server 2016", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38652", kind: overrideFixedBuild, product: "Microsoft SharePoint Enterprise Server 2016", from: "5215.1000", fixedBuild: "16.0.5215.1000"},
	{cve: "CVE-2021-38651", kind: overrideFixedBuild, product: "Microsoft SharePoint Server 2019", from: "10378.20002", fixedBuild: "16.0.10378.20002"},
	// 2022-Dec (FixedBuild "10393.20000" / "15601.20316" missing "16.0." prefix)
	{cve: "CVE-2022-44690", kind: overrideFixedBuild, product: "Microsoft SharePoint Server 2019", from: "10393.20000", fixedBuild: "16.0.10393.20000"},
	{cve: "CVE-2022-44693", kind: overrideFixedBuild, product: "Microsoft SharePoint Server 2019", from: "10393.20000", fixedBuild: "16.0.10393.20000"},
	{cve: "CVE-2022-44690", kind: overrideFixedBuild, product: "Microsoft SharePoint Server Subscription Edition", from: "15601.20316", fixedBuild: "16.0.15601.20316"},
	{cve: "CVE-2022-44693", kind: overrideFixedBuild, product: "Microsoft SharePoint Server Subscription Edition", from: "15601.20316", fixedBuild: "16.0.15601.20316"},

	// SQL Server Management Studio
	// 2026-Sep (CVE-2026-65669): FixedBuild "22.8.2" is the SSMS release number, not the build
	// number that installs report. SSMS 22 builds are 22.1.<Visual Studio build>: the 22.8.2
	// release notes say "Updated to Visual Studio 18.8.2 [12023.21]"
	// (https://learn.microsoft.com/en-us/ssms/release-notes-22), and
	// https://sqlserverbuilds.blogspot.com/2018/01/sql-server-management-studio-ssms.html maps
	// 22.8.2 to 22.1.12023.21. Left as a release number, every later build (e.g. 22.1.12210.168
	// for 22.10.1) would compare as older than the fix. SSMS 20.2's FixedBuild ("20.2.37.0",
	// CVE-2025-29803) was already a build number
	{cve: "CVE-2026-65669", kind: overrideFixedBuild, product: "SQL Server Management Studio 22", from: "22.8.2", fixedBuild: "22.1.12023.21"},

	// Microsoft Teams for Android (FixedBuild "1416/..." has numeric prefix before slash)
	// 2022-Feb (CVE-2022-21965, FixedBuild "1416/..." has numeric prefix)
	{cve: "CVE-2022-21965", kind: overrideFixedBuild, product: "Microsoft Teams for Android", from: "1416/1.0.0.2021040701", fixedBuild: "1.0.0.2021040701"},
	// 2025-Aug (CVE-2025-53783, FixedBuild "1416/..." has numeric prefix)
	{cve: "CVE-2025-53783", kind: overrideFixedBuild, product: "Microsoft Teams for Android", from: "1416/1.0.0.2025102802", fixedBuild: "1.0.0.2025102802"},

	// Teams Panels / Phones (FixedBuild "1449/..." has numeric prefix before slash)
	// 2025-Aug (CVE-2025-53783, FixedBuild "1449/..." has numeric prefix)
	{cve: "CVE-2025-53783", kind: overrideFixedBuild, product: "Teams Panels", from: "1449/1.0.97.2025102203", fixedBuild: "1.0.97.2025102203"},
	{cve: "CVE-2025-53783", kind: overrideFixedBuild, product: "Teams Phones", from: "1449/1.0.94.2025168802", fixedBuild: "1.0.94.2025168802"},

	// Microsoft Teams for iOS (FixedBuild has trailing parenthetical build ID)
	// 2025-Jul (CVE-2025-49731, FixedBuild has trailing parenthetical build ID)
	{cve: "CVE-2025-49731", kind: overrideFixedBuild, product: "Microsoft Teams for iOS", from: "7.10.1 (100772025102901)", fixedBuild: "7.10.1"},
	// 2025-Aug (CVE-2025-53783, FixedBuild has trailing parenthetical build ID)
	{cve: "CVE-2025-53783", kind: overrideFixedBuild, product: "Microsoft Teams for iOS", from: "7.10.1 (100772025102901)", fixedBuild: "7.10.1"},

	// Microsoft Visual Studio
	// 2021-Nov (VS 2015 Update 3 14.0.27550.0, FixedBuild "27550.00" missing "14.0." prefix)
	{cve: "CVE-2021-42277", kind: overrideFixedBuild, product: "Microsoft Visual Studio 2015 Update 3", from: "27550.00", fixedBuild: "14.0.27550.0"},
	// 2022-Jan (VS 2015 Update 3 14.0.27551.0, FixedBuild "27551.00" missing "14.0." prefix)
	{cve: "CVE-2022-21871", kind: overrideFixedBuild, product: "Microsoft Visual Studio 2015 Update 3", from: "27551.00", fixedBuild: "14.0.27551.0"},

	// Visual Studio Code
	// 2021-May (VS Code 1.56.0, FixedBuild "1.56" missing ".0" suffix)
	{cve: "CVE-2021-31211", kind: overrideFixedBuild, product: "Visual Studio Code", from: "1.56", fixedBuild: "1.56.0"},
	{cve: "CVE-2021-31214", kind: overrideFixedBuild, product: "Visual Studio Code", from: "1.56", fixedBuild: "1.56.0"},
	// 2021-Jul (VS Code 1.58.0, FixedBuild "1.58" missing ".0" suffix)
	{cve: "CVE-2021-34479", kind: overrideFixedBuild, product: "Visual Studio Code", from: "1.58", fixedBuild: "1.58.0"},
	{cve: "CVE-2021-34528", kind: overrideFixedBuild, product: "Visual Studio Code", from: "1.58", fixedBuild: "1.58.0"},
	// 2023-Jun (VS Code 1.79.0, FixedBuild "1.79" missing ".0" suffix)
	{cve: "CVE-2023-33144", kind: overrideFixedBuild, product: "Visual Studio Code", from: "1.79", fixedBuild: "1.79.0"},

	// Windows / Internet Explorer
	// 2020-Feb (UEFI/Secure Boot firmware, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{cve: "CVE-2020-0689", kind: overrideNoFixedBuild, product: "Windows 10 for x64-based Systems", from: "1.002"},
	// 2020-Jul (UEFI/Secure Boot firmware, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{cve: "ADV200011", kind: overrideNoFixedBuild, product: "Windows 10 for 32-bit Systems", from: "1.002"},
	{cve: "ADV200011", kind: overrideNoFixedBuild, product: "Windows 10 for x64-based Systems", from: "1.002"},
	// 2021-May (IE Cumulative, FixedBuild "6.0"/"6.1"/"6.2" matches OS major.minor but is a truncated IE revision)
	{cve: "CVE-2021-26419", kind: overrideNoFixedBuild, product: "Internet Explorer 9 on Windows Server 2008 for 32-bit Systems Service Pack 2", from: "6.0"},
	{cve: "CVE-2021-26419", kind: overrideNoFixedBuild, product: "Internet Explorer 9 on Windows Server 2008 for x64-based Systems Service Pack 2", from: "6.0"},
	{cve: "CVE-2021-26419", kind: overrideNoFixedBuild, product: "Internet Explorer 11 on Windows 7 for 32-bit Systems Service Pack 1", from: "6.1"},
	{cve: "CVE-2021-26419", kind: overrideNoFixedBuild, product: "Internet Explorer 11 on Windows 7 for x64-based Systems Service Pack 1", from: "6.1"},
	{cve: "CVE-2021-26419", kind: overrideNoFixedBuild, product: "Internet Explorer 11 on Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "6.1"},
	{cve: "CVE-2021-26419", kind: overrideNoFixedBuild, product: "Internet Explorer 11 on Windows Server 2012", from: "6.2"},
	// 2021-Jun (IE Cumulative, FixedBuild "1.0.0.0" is a revision number, not a Windows OS build)
	{cve: "CVE-2021-31959", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.0.0.0"},
	{cve: "CVE-2021-31959", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.0.0.0"},
	{cve: "CVE-2021-31959", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.0.0.0"},
	{cve: "CVE-2021-31959", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.0.0.0"},
	{cve: "CVE-2021-31971", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.0.0.0"},
	{cve: "CVE-2021-31971", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.0.0.0"},
	{cve: "CVE-2021-31971", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.0.0.0"},
	{cve: "CVE-2021-31971", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.0.0.0"},
	{cve: "CVE-2021-33742", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.0.0.0"},
	{cve: "CVE-2021-33742", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.0.0.0"},
	{cve: "CVE-2021-33742", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.0.0.0"},
	{cve: "CVE-2021-33742", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.0.0.0"},
	// 2021-Jul (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2021-34446", kind: overrideNoFixedBuild, product: "Windows 7 for 32-bit Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34446", kind: overrideNoFixedBuild, product: "Windows 7 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34446", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.001"},
	{cve: "CVE-2021-34446", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.001"},
	{cve: "CVE-2021-34446", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34446", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2021-34446", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2021-34446", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2021-34446", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2021-34447", kind: overrideNoFixedBuild, product: "Windows 7 for 32-bit Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34447", kind: overrideNoFixedBuild, product: "Windows 7 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34447", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.001"},
	{cve: "CVE-2021-34447", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.001"},
	{cve: "CVE-2021-34447", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34447", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2021-34447", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2021-34447", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2021-34447", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2021-34448", kind: overrideNoFixedBuild, product: "Windows 7 for 32-bit Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34448", kind: overrideNoFixedBuild, product: "Windows 7 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34448", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.001"},
	{cve: "CVE-2021-34448", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.001"},
	{cve: "CVE-2021-34448", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34448", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2021-34448", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2021-34497", kind: overrideNoFixedBuild, product: "Windows 7 for 32-bit Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34497", kind: overrideNoFixedBuild, product: "Windows 7 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34497", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.001"},
	{cve: "CVE-2021-34497", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.001"},
	{cve: "CVE-2021-34497", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34497", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2021-34497", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2021-34497", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2021-34497", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	// 2021-Aug (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2021-34480", kind: overrideNoFixedBuild, product: "Windows 7 for 32-bit Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34480", kind: overrideNoFixedBuild, product: "Windows 7 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34480", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.001"},
	{cve: "CVE-2021-34480", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.001"},
	{cve: "CVE-2021-34480", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-34480", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2021-34480", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	// 2021-Sep (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows 7 for 32-bit Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows 7 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2021-40444", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2021-Oct (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2021-41342", kind: overrideNoFixedBuild, product: "Windows 7 for 32-bit Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-41342", kind: overrideNoFixedBuild, product: "Windows 7 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-41342", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.001"},
	{cve: "CVE-2021-41342", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.001"},
	{cve: "CVE-2021-41342", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2021-41342", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2021-41342", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2021-41342", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2021-41342", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	// 2022-Mar (IE Cumulative, FixedBuild "1.1.0.0" is a revision number, not a Windows OS build)
	{cve: "CVE-2022-24502", kind: overrideNoFixedBuild, product: "Windows 7 for 32-bit Systems Service Pack 1", from: "1.1.0.0"},
	{cve: "CVE-2022-24502", kind: overrideNoFixedBuild, product: "Windows 7 for x64-based Systems Service Pack 1", from: "1.1.0.0"},
	{cve: "CVE-2022-24502", kind: overrideNoFixedBuild, product: "Windows 8.1 for 32-bit systems", from: "1.1.0.0"},
	{cve: "CVE-2022-24502", kind: overrideNoFixedBuild, product: "Windows 8.1 for x64-based systems", from: "1.1.0.0"},
	{cve: "CVE-2022-24502", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.1.0.0"},
	{cve: "CVE-2022-24502", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.1.0.0"},
	{cve: "CVE-2022-24502", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.1.0.0"},
	{cve: "CVE-2022-24502", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.1.0.0"},
	{cve: "CVE-2022-24502", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.1.0.0"},
	// 2022-Aug (UEFI/Secure Boot firmware, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{cve: "CVE-2022-34301", kind: overrideNoFixedBuild, product: "Windows 10 for 32-bit Systems", from: "1.002"},
	{cve: "CVE-2022-34301", kind: overrideNoFixedBuild, product: "Windows 10 for x64-based Systems", from: "1.002"},
	{cve: "CVE-2022-34302", kind: overrideNoFixedBuild, product: "Windows 10 for 32-bit Systems", from: "1.002"},
	{cve: "CVE-2022-34302", kind: overrideNoFixedBuild, product: "Windows 10 for x64-based Systems", from: "1.002"},
	{cve: "CVE-2022-34303", kind: overrideNoFixedBuild, product: "Windows 10 for 32-bit Systems", from: "1.002"},
	{cve: "CVE-2022-34303", kind: overrideNoFixedBuild, product: "Windows 10 for x64-based Systems", from: "1.002"},
	// 2023-Feb (IE Cumulative, FixedBuild "1.1.0.0" is a revision number, not a Windows OS build)
	{cve: "CVE-2023-21805", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.1.0.0"},
	{cve: "CVE-2023-21805", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.1.0.0"},
	{cve: "CVE-2023-21805", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.1.0.0"},
	{cve: "CVE-2023-21805", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.1.0.0"},
	{cve: "CVE-2023-21805", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.1.0.0"},
	{cve: "CVE-2023-21805", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.1.0.0"},
	{cve: "CVE-2023-21805", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.1.0.0"},
	{cve: "CVE-2023-21805", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.1.0.0"},
	// 2023-May (Windows 11 24H2 x64, FixedBuild "0.0.26200.4652" is a typo for "10.0.26100.4652" — the ARM64 entry has the correct value)
	{cve: "CVE-2023-24932", kind: overrideFixedBuild, product: "Windows 11 Version 24H2 for x64-based Systems", from: "0.0.26200.4652", fixedBuild: "10.0.26100.4652"},
	// 2023-May (IE Cumulative, FixedBuild "1.1.0.0" is a revision number, not a Windows OS build)
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.1.0.0"},
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.1.0.0"},
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.1.0.0"},
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.1.0.0"},
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.1.0.0"},
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.1.0.0"},
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.1.0.0"},
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.1.0.0"},
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.1.0.0"},
	{cve: "CVE-2023-29324", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.1.0.0"},
	// 2023-Jul (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2023-32046", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-35308", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2023-35308", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-35336", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2023-35336", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2023-Aug (IE Cumulative, FixedBuild "10.0.0.0" is a revision number, not a Windows OS build)
	{cve: "CVE-2023-35384", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "10.0.0.0"},
	{cve: "CVE-2023-35384", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "10.0.0.0"},
	// 2023-Sep (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2023-36805", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2023-36805", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-36805", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2023-36805", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-36805", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2023-36805", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2023-Oct (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2023-36436", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2023-36436", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-36436", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2023-36436", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2023-Nov (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2023-36017", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2023-36017", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-36017", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2023-36017", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-36017", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2023-36017", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2023-Dec (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2023-35628", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2023-35628", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-35628", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2023-35628", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2023-35628", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2023-Dec (UEFI/Secure Boot firmware, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{cve: "CVE-2023-35628", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.002"},
	// 2024-Jan (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2024-20652", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2024-20652", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2024-20652", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2024-20652", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2024-20652", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2024-20652", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2024-Jul (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2024-38112", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2024-38112", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2024-38112", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2024-38112", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2024-38112", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2024-38112", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2024-Aug (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2024-38178", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2024-38178", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2024-Sep (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2024-30073", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2024-30073", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2024-30073", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2024-30073", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2024-30073", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2024-30073", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2024-43461", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2024-43461", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2024-43461", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.001"},
	{cve: "CVE-2024-43461", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	// 2024-Nov (IE Cumulative, FixedBuild "1.001" is a revision number, not a Windows OS build)
	{cve: "CVE-2024-43451", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.001"},
	{cve: "CVE-2024-43451", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2024-43451", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2024-43451", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2024-43451", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.001"},
	{cve: "CVE-2024-43451", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.001"},
	{cve: "CVE-2024-43451", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.001"},
	{cve: "CVE-2024-43451", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.001"},
	// 2025-Jan (IE Cumulative, FixedBuild "1.002" is a revision number, not a Windows OS build)
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.002"},
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.002"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.002"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.002"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.002"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.002"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.002"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.002"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.002"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.002"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.002"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.002"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.002"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.002"},
	// 2025-Jan (IE Cumulative, FixedBuild "1.003" is a revision number, not a Windows OS build)
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.003"},
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.003"},
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.003"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.003"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.003"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.003"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.003"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.003"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.003"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.003"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.003"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.003"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.003"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.003"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.003"},
	// 2025-Jan (IE Cumulative, FixedBuild "1.007" is a revision number, not a Windows OS build)
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21189", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21268", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21269", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21276", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21328", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21329", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.007"},
	{cve: "CVE-2025-21332", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.007"},
	// 2025-Mar (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{cve: "CVE-2025-21247", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.000"},
	{cve: "CVE-2025-21247", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-21247", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-21247", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-21247", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2025-21247", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	// 2025-Apr (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.000"},
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2025-27737", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	// 2025-May (IE Cumulative, FixedBuild "1.003" is a revision number, not a Windows OS build)
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.003"},
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.003"},
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.003"},
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.003"},
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.003"},
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.003"},
	{cve: "CVE-2025-30397", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.003"},
	// 2025-Jun (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{cve: "CVE-2025-33053", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2025-33053", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	// 2025-Sep (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.000"},
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2025-54107", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2025-54917", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	// 2025-Oct (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.000"},
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2025-58739", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2025-59208", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2025-59295", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	// 2026-Mar (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{cve: "CVE-2026-23674", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2026-23674", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2026-23674", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2026-23674", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	// 2026-Apr (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{cve: "CVE-2026-32077", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2026-32077", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2026-32077", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2026-32077", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	// 2026-Jun (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{cve: "CVE-2026-45592", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2026-45592", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},
	// 2026-Jul (IE Cumulative, FixedBuild "1.000" is a revision number, not a Windows OS build)
	{cve: "CVE-2026-50480", kind: overrideNoFixedBuild, product: "Windows Server 2012", from: "1.000"},
	{cve: "CVE-2026-50480", kind: overrideNoFixedBuild, product: "Windows Server 2012 (Server Core installation)", from: "1.000"},
	{cve: "CVE-2026-50480", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2", from: "1.000"},
	{cve: "CVE-2026-50480", kind: overrideNoFixedBuild, product: "Windows Server 2012 R2 (Server Core installation)", from: "1.000"},

	// Windows OS (FixedBuild leaked from a sibling servicing branch: a single Vendor Fix
	// Remediation grouped products from multiple servicing branches but specified only
	// one branch's build value; rewrite only the third component of "10.0.X.Y" to the
	// product's known servicing-branch build major, preserving the per-CVE fourth
	// component that is shared across branches.)
	// 2023-Feb (Win11 21H2 (ARM64) tagged 10.0.22621.x; Win11 21H2 (x64) tagged 10.0.22621.x)
	{cve: "CVE-2023-21684", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21684", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21685", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21685", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21686", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21686", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21687", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21687", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21688", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21688", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21689", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21689", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21690", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21690", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21691", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21691", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21692", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21692", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21693", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21693", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21694", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21694", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21695", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21695", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21700", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21700", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21701", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21701", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21702", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21702", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21797", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21797", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21798", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21798", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21799", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21799", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21801", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21801", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21802", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21802", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21804", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21804", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21805", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21805", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21811", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21811", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21812", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21812", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21813", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21813", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21816", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21816", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21817", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21817", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21818", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21818", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21819", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21819", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21820", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21820", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21822", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21822", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21823", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-21823", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-23376", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	{cve: "CVE-2023-23376", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.22621.1574", fixedBuild: "10.0.22000.1574"},
	// 2023-Dec (Win11 23H2 (ARM64) tagged 10.0.22621.x)
	{cve: "CVE-2023-20588", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-21740", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-35628", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-35630", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-35631", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-35634", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-35635", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-35639", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-35641", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-35642", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-35644", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-36003", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-36004", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-36005", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-36006", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-36011", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-36391", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	{cve: "CVE-2023-36696", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.2861", fixedBuild: "10.0.22631.2861"},
	// 2024-Aug (Win11 21H2 (ARM64) tagged 10.0.19044.x; Win11 21H2 (x64) tagged 10.0.19044.x; Win11 24H2 (x64) tagged 10.0.22621.x)
	{cve: "CVE-2022-2601", kind: overrideFixedBuild, product: "Windows 11 Version 24H2 for x64-based Systems", from: "10.0.22621.5189", fixedBuild: "10.0.26100.5189"},
	{cve: "CVE-2023-40547", kind: overrideFixedBuild, product: "Windows 11 Version 24H2 for x64-based Systems", from: "10.0.22621.5189", fixedBuild: "10.0.26100.5189"},
	{cve: "CVE-2024-21302", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for ARM64-based Systems", from: "10.0.19044.5737", fixedBuild: "10.0.22000.5737"},
	{cve: "CVE-2024-21302", kind: overrideFixedBuild, product: "Windows 11 version 21H2 for x64-based Systems", from: "10.0.19044.5737", fixedBuild: "10.0.22000.5737"},
	// 2024-Sep (Win11 23H2 (x64) tagged 10.0.22621.x)
	{cve: "CVE-2024-43495", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for x64-based Systems", from: "10.0.22621.3880", fixedBuild: "10.0.22631.3880"},
	// 2025-Jun (Win11 23H2 (ARM64) tagged 10.0.22621.x; Win11 23H2 (x64) tagged 10.0.22621.x)
	{cve: "CVE-2025-47969", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for ARM64-based Systems", from: "10.0.22621.5335", fixedBuild: "10.0.22631.5335"},
	{cve: "CVE-2025-47969", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for x64-based Systems", from: "10.0.22621.5335", fixedBuild: "10.0.22631.5335"},
	// 2025-Jul (Server 2025 tagged 10.0.26200.x; Server 2025 Core tagged 10.0.26200.x)
	{cve: "CVE-2025-49735", kind: overrideFixedBuild, product: "Windows Server 2025", from: "10.0.26200.4349", fixedBuild: "10.0.26100.4349"},
	{cve: "CVE-2025-49735", kind: overrideFixedBuild, product: "Windows Server 2025 (Server Core installation)", from: "10.0.26200.4349", fixedBuild: "10.0.26100.4349"},
	// 2025-Aug (Win11 22H2 (ARM64) tagged 10.0.22631.x; Win11 23H2 (x64) tagged 10.0.22621.x)
	{cve: "CVE-2025-53789", kind: overrideFixedBuild, product: "Windows 11 Version 22H2 for ARM64-based Systems", from: "10.0.22631.5624", fixedBuild: "10.0.22621.5624"},
	{cve: "CVE-2025-53789", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for x64-based Systems", from: "10.0.22621.5624", fixedBuild: "10.0.22631.5624"},
	{cve: "CVE-2025-55230", kind: overrideFixedBuild, product: "Windows 11 Version 23H2 for x64-based Systems", from: "10.0.22621.5624", fixedBuild: "10.0.22631.5624"},
	// 2025-Sep (Win11 22H2 (ARM64) tagged 10.0.22631.x; Win11 22H2 (x64) tagged 10.0.22631.x)
	{cve: "CVE-2025-59220", kind: overrideFixedBuild, product: "Windows 11 Version 22H2 for ARM64-based Systems", from: "10.0.22631.5909", fixedBuild: "10.0.22621.5909"},
	{cve: "CVE-2025-59220", kind: overrideFixedBuild, product: "Windows 11 Version 22H2 for x64-based Systems", from: "10.0.22631.5909", fixedBuild: "10.0.22621.5909"},
	// 2025-Oct (Win11 22H2 (ARM64) tagged 10.0.22631.x; Win11 22H2 (x64) tagged 10.0.22631.x)
	{cve: "CVE-2025-59289", kind: overrideFixedBuild, product: "Windows 11 Version 22H2 for ARM64-based Systems", from: "10.0.22631.5909", fixedBuild: "10.0.22621.5909"},
	{cve: "CVE-2025-59289", kind: overrideFixedBuild, product: "Windows 11 Version 22H2 for x64-based Systems", from: "10.0.22631.5909", fixedBuild: "10.0.22621.5909"},
	{cve: "CVE-2025-59290", kind: overrideFixedBuild, product: "Windows 11 Version 22H2 for ARM64-based Systems", from: "10.0.22631.5909", fixedBuild: "10.0.22621.5909"},
	{cve: "CVE-2025-59290", kind: overrideFixedBuild, product: "Windows 11 Version 22H2 for x64-based Systems", from: "10.0.22631.5909", fixedBuild: "10.0.22621.5909"},
	{cve: "CVE-2025-59502", kind: overrideFixedBuild, product: "Windows 11 Version 22H2 for ARM64-based Systems", from: "10.0.22631.5909", fixedBuild: "10.0.22621.5909"},
	{cve: "CVE-2025-59502", kind: overrideFixedBuild, product: "Windows 11 Version 22H2 for x64-based Systems", from: "10.0.22631.5909", fixedBuild: "10.0.22621.5909"},
	// 2025-Dec (Win11 25H2 (ARM64) tagged 10.0.26100.x; Win11 25H2 (x64) tagged 10.0.26100.x)
	{cve: "CVE-2025-54100", kind: overrideFixedBuild, product: "Windows 11 Version 25H2 for ARM64-based Systems", from: "10.0.26100.7392", fixedBuild: "10.0.26200.7392"},
	{cve: "CVE-2025-54100", kind: overrideFixedBuild, product: "Windows 11 Version 25H2 for x64-based Systems", from: "10.0.26100.7392", fixedBuild: "10.0.26200.7392"},
	// 2026-Mar (Win11 25H2 (ARM64) tagged 10.0.26100.x)
	{cve: "CVE-2026-25172", kind: overrideFixedBuild, product: "Windows 11 Version 25H2 for ARM64-based Systems", from: "10.0.26100.7982", fixedBuild: "10.0.26200.7982"},
	{cve: "CVE-2026-25173", kind: overrideFixedBuild, product: "Windows 11 Version 25H2 for ARM64-based Systems", from: "10.0.26100.7982", fixedBuild: "10.0.26200.7982"},
	{cve: "CVE-2026-26111", kind: overrideFixedBuild, product: "Windows 11 Version 25H2 for ARM64-based Systems", from: "10.0.26100.7982", fixedBuild: "10.0.26200.7982"},
	// 2026-Aug (Win11 24H2 (ARM64) hotpatch tagged 10.0.26200.x)
	{cve: "CVE-2026-62727", kind: overrideFixedBuild, product: "Windows 11 Version 24H2 for ARM64-based Systems", from: "10.0.26200.9106", fixedBuild: "10.0.26100.9106"},

	// overrideExcludeVendorFix: CVRF remediations cannot express that one update
	// is a prerequisite of another, so a monthly hotpatch whose CVE is only
	// fixed by a follow-up update is listed side by side with that update as if
	// either one fixed it. Kept, the monthly hotpatch would gate the follow-up's
	// fixed build (see appendVendorFixConditions) and hide hosts that applied
	// only the monthly hotpatch, so it is excluded. An excluded product stays
	// covered by its other Vendor Fix remediations; buildDetections fails when
	// none is left, unless each was moved by overrideAddVendorFix.
	//
	// A remediation CVRF gets wrong is excluded here and added back corrected by
	// overrideAddVendorFix. overrideFixedBuild cannot express these corrections:
	// its key is the FixedBuild, which a follow-up update may share with the
	// cumulative update.
	// CVE-2022-23278: see its overrideAddVendorFix.
	{cve: "CVE-2022-23278", kind: overrideExcludeVendorFix, product: "Microsoft Defender for Endpoint for Windows on Windows Server 2022 Datacenter: Azure Edition", kbID: "5011580"},
	// 2026-Aug Windows 11: KB5123607 ("OS Builds 26100.9165 and 26200.9165";
	// and KB5123273 for Pluton-as-TPM devices), "offered after the August 2026
	// security hotpatch update (KB5120994) is installed", fix CVE-2026-6726 and
	// CVE-2026-66804 on hotpatch-enrolled devices (CVE-2026-6726 FAQ "Do I need
	// to do anything additional ..."; https://support.microsoft.com/help/5123607,
	// https://support.microsoft.com/help/5123273).
	// Known gap, accepted: KB5123273 is required *in addition* to KB5123607 on
	// Pluton-as-TPM devices only, and whether a host is one is not in the scan
	// result, so either KB clears a host and a Pluton host with KB5123607 but
	// not KB5123273 is missed. Requiring both instead would report every
	// non-Pluton hotpatch host, which is never offered KB5123273, until its
	// next update.
	{cve: "CVE-2026-6726", kind: overrideExcludeVendorFix, product: "Windows 11 Version 24H2 for ARM64-based Systems", kbID: "5120994"},
	{cve: "CVE-2026-6726", kind: overrideExcludeVendorFix, product: "Windows 11 Version 24H2 for x64-based Systems", kbID: "5120994"},
	{cve: "CVE-2026-6726", kind: overrideExcludeVendorFix, product: "Windows 11 Version 25H2 for ARM64-based Systems", kbID: "5120994"},
	{cve: "CVE-2026-6726", kind: overrideExcludeVendorFix, product: "Windows 11 Version 25H2 for x64-based Systems", kbID: "5120994"},
	// CVRF of CVE-2026-66804 does not list either follow-up update, so only the
	// cumulative update remains: hotpatch-enrolled hosts that installed
	// KB5123607 (.9165) are reported by "version < .9168" until their next
	// update. Accepted: reporting them beats hiding hosts with only KB5120994.
	{cve: "CVE-2026-66804", kind: overrideExcludeVendorFix, product: "Windows 11 Version 24H2 for ARM64-based Systems", kbID: "5120994"},
	{cve: "CVE-2026-66804", kind: overrideExcludeVendorFix, product: "Windows 11 Version 24H2 for x64-based Systems", kbID: "5120994"},
	{cve: "CVE-2026-66804", kind: overrideExcludeVendorFix, product: "Windows 11 Version 25H2 for ARM64-based Systems", kbID: "5120994"},
	{cve: "CVE-2026-66804", kind: overrideExcludeVendorFix, product: "Windows 11 Version 25H2 for x64-based Systems", kbID: "5120994"},
	// 2026-Aug Windows Server 2022: the monthly hotpatch KB5120229 is followed
	// by KB5123303; see their overrideAddVendorFix. KB5123303 itself is listed wrong
	// and added back corrected there.
	{cve: "CVE-2026-6726", kind: overrideExcludeVendorFix, product: "Windows Server 2022", kbID: "5120229"},
	{cve: "CVE-2026-6726", kind: overrideExcludeVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5120229"},
	{cve: "CVE-2026-6727", kind: overrideExcludeVendorFix, product: "Windows Server 2022", kbID: "5120229"},
	{cve: "CVE-2026-6727", kind: overrideExcludeVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5120229"},
	{cve: "CVE-2026-66799", kind: overrideExcludeVendorFix, product: "Windows Server 2022", kbID: "5120229"},
	{cve: "CVE-2026-66799", kind: overrideExcludeVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5120229"},
	{cve: "CVE-2026-6726", kind: overrideExcludeVendorFix, product: "Windows Server 2022", kbID: "5123303"},
	{cve: "CVE-2026-6726", kind: overrideExcludeVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5123303"},
	{cve: "CVE-2026-6727", kind: overrideExcludeVendorFix, product: "Windows Server 2022", kbID: "5123303"},
	{cve: "CVE-2026-6727", kind: overrideExcludeVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5123303"},
	{cve: "CVE-2026-66799", kind: overrideExcludeVendorFix, product: "Windows Server 2022", kbID: "5123303"},
	{cve: "CVE-2026-66799", kind: overrideExcludeVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5123303"},

	// overrideAddVendorFix: Vendor Fix remediations added to a product CVRF
	// lists with a Vendor Fix of its own; buildDetections fails on one it does
	// not. Products CVRF omits altogether are overrideAddProduct's.
	//
	// A hotpatch is otherwise listed beside its month's cumulative update, which
	// fixes the hosts that do not take hotpatches. Where it is the only fix,
	// nothing such a host can install satisfies the KB criterion, and the CVE is
	// reported on it for good. The baseline that followed the hotpatch is added
	// as the other way to be fixed: it is what a hotpatch-enrolled host installs
	// next, and it carries the fixes of the hotpatches before it, otherwise the
	// host would lose them on taking it and every hotpatch after it would have to
	// ship them again. Its fixed build is gated on the hotpatch's KB (see
	// appendVendorFixConditions), so a hotpatched host below it is not reported.
	// CVE-2022-23278 — Microsoft Defender for Endpoint Spoofing Vulnerability.
	// The hotpatch KB5011580 is listed under "Microsoft Defender for Endpoint
	// for Windows on Windows Server 2022 Datacenter: Azure Edition", apart
	// from the cumulative update KB5011497. Everywhere else CVRF lists a
	// hotpatch under the same product as its cumulative update, so it is
	// moved there.
	{cve: "CVE-2022-23278", kind: overrideAddVendorFix, product: "Microsoft Defender for Endpoint for Windows on Windows Server 2022", kbID: "5011580", fixedBuild: "10.0.20348.580", hotpatch: true},
	// CVE-2023-24898 — Windows SMB Denial of Service Vulnerability. Its FAQ:
	// "This vulnerability only affects the hotpatch version of Windows Server
	// 2022. If you are not running this version of the operating system, no
	// action is required for this vulnerability." The May 2023 hotpatch
	// KB5026456 is followed by the June one (KB5027319) and then by the July
	// 2023 baseline, KB5028171 (10.0.20348.1850).
	// The vulnerability is in what the hotpatch version runs and the other
	// does not, so the May 2023 cumulative update KB5026370 does not fix it:
	// a host on it is not affected, rather than fixed. Listing it would claim
	// a fix nothing records. The baseline is where a hotpatched host stays
	// fixed, so it is taken, as for any later entry; the hosts left reported
	// are those still on a May or June 2023 cumulative update.
	{cve: "CVE-2023-24898", kind: overrideAddVendorFix, product: "Windows Server 2022", kbID: "5028171", fixedBuild: "10.0.20348.1850"},
	{cve: "CVE-2023-24898", kind: overrideAddVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5028171", fixedBuild: "10.0.20348.1850"},
	// 2026-Aug Windows Server 2022: KB5123303 ("OS Build 20348.5440"),
	// "offered after the August 2026 security hotpatch update (KB5120229) is
	// installed" and applying "only to Windows Server, version 2022 devices
	// enrolled in hotpatch updates", fixes CVE-2026-6726, CVE-2026-6727 and
	// CVE-2026-66799 (CVE-2026-6726 / CVE-2026-6727 FAQ;
	// https://support.microsoft.com/help/5123303). CVRF lists it as a
	// "Security Update" with the cumulative update's FixedBuild .5499; it is
	// taken as the hotpatch-track fix at its article's build instead, so a host
	// that installed it is cleared by its KB whether or not the build moves.
	{cve: "CVE-2026-6726", kind: overrideAddVendorFix, product: "Windows Server 2022", kbID: "5123303", fixedBuild: "10.0.20348.5440", hotpatch: true},
	{cve: "CVE-2026-6726", kind: overrideAddVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5123303", fixedBuild: "10.0.20348.5440", hotpatch: true},
	{cve: "CVE-2026-6727", kind: overrideAddVendorFix, product: "Windows Server 2022", kbID: "5123303", fixedBuild: "10.0.20348.5440", hotpatch: true},
	{cve: "CVE-2026-6727", kind: overrideAddVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5123303", fixedBuild: "10.0.20348.5440", hotpatch: true},
	{cve: "CVE-2026-66799", kind: overrideAddVendorFix, product: "Windows Server 2022", kbID: "5123303", fixedBuild: "10.0.20348.5440", hotpatch: true},
	{cve: "CVE-2026-66799", kind: overrideAddVendorFix, product: "Windows Server 2022 (Server Core installation)", kbID: "5123303", fixedBuild: "10.0.20348.5440", hotpatch: true},
}
