package csaf

import (
	"fmt"
	"slices"
	"strings"

	"github.com/pkg/errors"

	csafTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/csaf"
)

// fixProductTree repairs doc where the published advisory gets its product
// tree wrong, and rewrites its product references to product_ids, so the
// rest of the extractor reads a CSAF document that says what the advisory
// means. It runs on the document as fetched, before anything else reads it.
//
// Two things are kept apart: where a leaf sits in the tree, which says what
// product it is, and which references cover it, which says what score,
// threat or remediation applies to it. Fortinet scopes references by product
// branch name (see resolveReferences), written for the leaves it published
// under that branch, so coverage follows where a leaf was published, wherever
// a repair moves it.
//
// First the advisory-bound repairs of treeFixes, each written out in full and
// hard-erroring when the advisory no longer matches it. Then every
// known_not_affected product_id the tree does not define is defined (see
// defineNotAffected). Last, the references are resolved to product_ids.
func fixProductTree(doc *csafTypes.CSAF) error {
	// An advisory without an entry repairs nothing of its own, but still gets
	// its known_not_affected products defined and its references resolved.
	return treeFixes[doc.Document.Tracking.ID].repair(doc)
}

// repair applies f to doc, then defines its known_not_affected products and
// resolves its references (see fixProductTree).
func (f treeFix) repair(doc *csafTypes.CSAF) error {
	cov := indexCoverage(doc.ProductTree.Branches)
	renamed := make(map[csafTypes.ProductID]csafTypes.ProductID)
	if err := f.apply(doc, cov, renamed); err != nil {
		return errors.Wrapf(err, "apply the tree fix of %s", doc.Document.Tracking.ID)
	}
	if err := defineNotAffected(doc, cov, renamed); err != nil {
		return errors.Wrap(err, "define known_not_affected products")
	}
	if err := resolveReferences(doc, cov); err != nil {
		return errors.Wrap(err, "resolve product references")
	}
	return nil
}

// coverage maps each product branch name to the product_ids that a reference
// naming the branch covers: the leaves published under it, under their
// repaired product_ids wherever a repair moves them, and the
// known_not_affected products defined from an entry spelled after it.
type coverage map[string][]csafTypes.ProductID

// indexCoverage records the leaves under each product branch of the tree as
// published. A branch name may repeat (one branch per leaf in some
// advisories); its leaves accumulate.
func indexCoverage(branches []csafTypes.Branch) coverage {
	cov := make(coverage)
	var walk func(bs []csafTypes.Branch, names []string)
	walk = func(bs []csafTypes.Branch, names []string) {
		for _, b := range bs {
			ns := names
			switch b.Category {
			case "product", "product_name":
				ns = append(slices.Clip(names), b.Name)
			default:
			}
			if b.Product != nil && b.Product.ProductID != "" {
				for _, n := range ns {
					cov[n] = append(cov[n], b.Product.ProductID)
				}
			}
			walk(b.Branches, ns)
		}
	}
	walk(branches, nil)
	return cov
}

// treeFix is the repair of one advisory: product branches whose leaves are
// filed under the wrong product or with the wrong version, and the
// product_status lists rewritten to match.
type treeFix struct {
	branches []branchFix
	statuses []statusFix
}

// branchFix rewrites leaves of one product branch. leaves is the branch's
// every leaf name as published, in order, so any change to the branch retires
// the fix loudly instead of repairing the wrong leaf; to maps a leaf's index
// to what it is. A leaf moved to another product goes to the branch of that
// name, a sibling created if the tree has none, and stays covered by the
// references naming the branch it was published under.
type branchFix struct {
	name   string
	leaves []string
	to     map[int]leafTarget
}

// leafTarget is the product and the version expression a leaf is read as. Its
// product_id becomes "<product> <version>".
type leafTarget struct {
	product string
	version string
}

// statusFix rewrites entries of a product_status list, in every
// vulnerability object carrying it. from is the list written out in full as
// published, so any change to it retires the fix loudly instead of rewriting
// the wrong entry; to maps an entry's index to what becomes of it. Positions
// matter where a product_id repeats: a list names the Cloud and the
// on-premise leaf with one product_id in the same order as the tree.
type statusFix struct {
	list statusList
	from []csafTypes.ProductID
	to   map[int]statusTarget
}

// statusTarget is what becomes of a product_status entry: replaced by
// productID, or dropped.
type statusTarget struct {
	productID csafTypes.ProductID
	drop      bool
}

// statusList names a product_status list by its CSAF field name.
type statusList string

const (
	knownAffected    statusList = "known_affected"
	knownNotAffected statusList = "known_not_affected"
)

// of returns the product_status list of v that l names. It errors on any
// other value, rather than defaulting to one of the lists.
func (l statusList) of(v *csafTypes.Vulnerability) (*[]csafTypes.ProductID, error) {
	switch l {
	case knownAffected:
		return &v.ProductStatus.KnownAffected, nil
	case knownNotAffected:
		return &v.ProductStatus.KnownNotAffected, nil
	default:
		return nil, errors.Errorf("unexpected product_status list. expected: %q, actual: %q", []statusList{knownAffected, knownNotAffected}, l)
	}
}

// apply repairs doc, keeping cov in step with the leaves it renames and
// recording in renamed, for each product_status entry it rewrites, the entry
// as published.
func (f treeFix) apply(doc *csafTypes.CSAF, cov coverage, renamed map[csafTypes.ProductID]csafTypes.ProductID) error {
	for _, bf := range f.branches {
		if err := bf.apply(doc, cov); err != nil {
			return errors.Wrapf(err, "branch %q", bf.name)
		}
	}
	for _, sf := range f.statuses {
		if err := sf.apply(doc, renamed); err != nil {
			return errors.Wrapf(err, "%s %q", sf.list, sf.from)
		}
	}
	return nil
}

func (bf branchFix) apply(doc *csafTypes.CSAF, cov coverage) error {
	for j := range bf.to {
		if j < 0 || j >= len(bf.leaves) {
			return errors.Errorf("leaf %d is out of the %d published", j, len(bf.leaves))
		}
	}
	parent, i, err := findProductBranch(&doc.ProductTree.Branches, bf.name)
	if err != nil {
		return errors.Wrap(err, "find branch")
	}
	branch := &(*parent)[i]
	if names := func() []string {
		ns := make([]string, 0, len(branch.Branches))
		for _, b := range branch.Branches {
			ns = append(ns, b.Name)
		}
		return ns
	}(); !slices.Equal(names, bf.leaves) {
		return errors.Errorf("unexpected leaves. expected: %q, actual: %q; the tree fix is stale", bf.leaves, names)
	}

	defined := productIDs(doc.ProductTree.Branches)

	// moved keeps the leaves per target product; products keeps the targets in
	// the order their first leaf comes, so new branches follow the tree. The
	// branch's coverage is rebuilt with every leaf it published, moved or not,
	// under its repaired product_id.
	var (
		kept     []csafTypes.Branch
		moved    = make(map[string][]csafTypes.Branch)
		products []string
		covered  = make([]csafTypes.ProductID, 0, len(branch.Branches))
	)
	for j, leaf := range branch.Branches {
		t, ok := bf.to[j]
		if !ok {
			kept = append(kept, leaf)
			if leaf.Product != nil {
				covered = append(covered, leaf.Product.ProductID)
			}
			continue
		}
		if leaf.Product == nil {
			return errors.Errorf("leaf %q has no product", leaf.Name)
		}
		pid := csafTypes.ProductID(fmt.Sprintf("%s %s", t.product, t.version))
		if _, ok := defined[pid]; ok && pid != leaf.Product.ProductID {
			return errors.Errorf("leaf %q would become %q, which the tree already defines", leaf.Name, pid)
		}
		leaf.Name = fmt.Sprintf("%s/%s", t.product, t.version)
		leaf.Product.Name = t.product
		leaf.Product.ProductID = pid
		covered = append(covered, pid)
		if t.product == bf.name {
			kept = append(kept, leaf)
			continue
		}
		if _, ok := moved[t.product]; !ok {
			products = append(products, t.product)
		}
		moved[t.product] = append(moved[t.product], leaf)
	}
	branch.Branches = kept
	cov[bf.name] = covered

	for _, product := range products {
		p, k, err := findProductBranch(&doc.ProductTree.Branches, product)
		switch {
		case err == nil:
			(*p)[k].Branches = append((*p)[k].Branches, moved[product]...)
		case errors.Is(err, errNoProductBranch):
			*parent = append(*parent, csafTypes.Branch{Category: "product", Name: product, Branches: moved[product]})
		default:
			return errors.Wrap(err, "find branch to move leaves to")
		}
	}
	return nil
}

// apply rewrites the list in every vulnerability object carrying it, and
// records in renamed, for each entry it replaces, the entry as published.
func (sf statusFix) apply(doc *csafTypes.CSAF, renamed map[csafTypes.ProductID]csafTypes.ProductID) error {
	for j, t := range sf.to {
		if j < 0 || j >= len(sf.from) {
			return errors.Errorf("entry %d is out of the %d published", j, len(sf.from))
		}
		if t.drop == (t.productID != "") {
			return errors.Errorf("entry %d must either be dropped or get a product_id, not %+v", j, t)
		}
	}
	fixed := make([]csafTypes.ProductID, 0, len(sf.from))
	for j, pid := range sf.from {
		t, ok := sf.to[j]
		switch {
		case !ok:
			fixed = append(fixed, pid)
		case t.drop:
		default:
			fixed = append(fixed, t.productID)
			renamed[t.productID] = pid
		}
	}

	n := 0
	for i := range doc.Vulnerabilities {
		l, err := sf.list.of(&doc.Vulnerabilities[i])
		if err != nil {
			return errors.Wrap(err, "select product_status list")
		}
		if slices.Equal(*l, sf.from) {
			*l = slices.Clone(fixed)
			n++
		}
	}
	if n == 0 {
		return errors.New("no vulnerability has the list; the tree fix is stale")
	}
	return nil
}

// errNoProductBranch reports that the tree has no product branch of a name.
var errNoProductBranch = errors.New("no product branch")

// findProductBranch returns the slice holding the one product branch named
// name, at whatever depth of bs it sits, and its index there. The slice is
// the tree's own, so appending to it adds a sibling in the tree. It errors
// when there is none (errNoProductBranch), or more than one.
func findProductBranch(bs *[]csafTypes.Branch, name string) (*[]csafTypes.Branch, int, error) {
	var (
		found *[]csafTypes.Branch
		at    int
		n     int
	)
	var walk func(bs *[]csafTypes.Branch)
	walk = func(bs *[]csafTypes.Branch) {
		for i := range *bs {
			b := &(*bs)[i]
			if b.Category == "product" && b.Name == name {
				found, at = bs, i
				n++
			}
			walk(&b.Branches)
		}
	}
	walk(bs)
	switch n {
	case 0:
		return nil, 0, errors.Wrapf(errNoProductBranch, "%q", name)
	case 1:
		return found, at, nil
	default:
		return nil, 0, errors.Errorf("%d product branches %q", n, name)
	}
}

// productIDs returns every product_id the tree defines.
func productIDs(bs []csafTypes.Branch) map[csafTypes.ProductID]struct{} {
	ids := make(map[csafTypes.ProductID]struct{})
	var walk func(bs []csafTypes.Branch)
	walk = func(bs []csafTypes.Branch) {
		for _, b := range bs {
			if b.Product != nil {
				ids[b.Product.ProductID] = struct{}{}
			}
			walk(b.Branches)
		}
	}
	walk(bs)
	return ids
}

// fixedRelease returns the version of the fixed release that a
// known_not_affected product_id the tree leaves undefined names under branch.
// Fortinet builds those product_ids from the vendor_fix text, as
// "<branch>-<X>" where the text reads "Upgrade to <X> or above": X is the
// release ("FortiOS-7.4.8"), or the release yet to ship, prefixed with
// "upcoming" (see trimUpcoming). The version is returned for the leaf's name;
// the product_id is kept as written, since the lists reference it. Anything
// else reports false, so a new spelling is added here or repaired in
// treeFixes by hand rather than read by shape. The branch is given, not
// parsed, since product names carry hyphens too ("FortiNAC-F").
func fixedRelease(pid csafTypes.ProductID, branch string) (string, bool) {
	rest, ok := strings.CutPrefix(string(pid), fmt.Sprintf("%s-", branch))
	if !ok {
		return "", false
	}
	rest = trimUpcoming(rest)
	for c := range strings.SplitSeq(rest, ".") {
		if c == "" || strings.Trim(c, "0123456789") != "" {
			return "", false
		}
	}
	return rest, true
}

// trimUpcoming drops the "upcoming" that the vendor_fix text puts before a
// fixed release yet to ship ("Upgrade to upcoming  7.5.2 or above"), with the
// spaces after it (two, one in FG-IR-23-385), so "upcoming  7.5.2" reads as
// "7.5.2". Fortinet leaves the word in once the release ships, and the
// release is what is not affected either way.
func trimUpcoming(s string) string {
	if after, ok := strings.CutPrefix(s, "upcoming "); ok {
		return strings.TrimLeft(after, " ")
	}
	return s
}

// branchOf returns the one product branch of branches under which pid names a
// fixed release (see fixedRelease), and that release.
func branchOf(pid csafTypes.ProductID, branches []string) (string, string, error) {
	var (
		branch, version string
		n               int
	)
	for _, b := range branches {
		if ver, ok := fixedRelease(pid, b); ok {
			branch, version = b, ver
			n++
		}
	}
	switch n {
	case 0:
		return "", "", errors.Errorf("unexpected undefined known_not_affected product %q", pid)
	case 1:
		return branch, version, nil
	default:
		return "", "", errors.Errorf("undefined known_not_affected product %q matches %d branches", pid, n)
	}
}

// defineNotAffected defines, as a product_version leaf under its product
// branch, every known_not_affected product_id that the tree does not define.
// Fortinet lists the fixed releases that way (2083 of the 3723
// known_not_affected entries across the corpus as of 2026-09); defining them
// makes the tree say what the list names. A product_id of any other shape, or
// whose branch the tree lacks, hard-errors.
//
// The leaf sits under the branch its product_id names, and is covered by the
// references naming the branch the entry named as published: a fixed Cloud
// release the advisory listed as "FortiManager-7.4.3" and treeFixes renamed
// "FortiManager Cloud-7.4.3" is a FortiManager Cloud leaf, scored by what was
// written for FortiManager. An entry as published of no known shape (repaired
// in treeFixes to one) is covered by the branch it sits under.
func defineNotAffected(doc *csafTypes.CSAF, cov coverage, renamed map[csafTypes.ProductID]csafTypes.ProductID) error {
	defined := productIDs(doc.ProductTree.Branches)
	var branches []string
	var walk func(bs []csafTypes.Branch)
	walk = func(bs []csafTypes.Branch) {
		for _, b := range bs {
			if b.Category == "product" {
				branches = append(branches, b.Name)
			}
			walk(b.Branches)
		}
	}
	walk(doc.ProductTree.Branches)

	for _, v := range doc.Vulnerabilities {
		for _, pid := range v.ProductStatus.KnownNotAffected {
			if _, ok := defined[pid]; ok {
				continue
			}
			branch, version, err := branchOf(pid, branches)
			if err != nil {
				return errors.Wrapf(err, "place a product of %q", v.CVE)
			}
			coveredBy := branch
			if published, ok := renamed[pid]; ok {
				if b, _, err := branchOf(published, branches); err == nil {
					coveredBy = b
				}
			}
			parent, i, err := findProductBranch(&doc.ProductTree.Branches, branch)
			if err != nil {
				return errors.Wrapf(err, "find branch of %q", pid)
			}
			(*parent)[i].Branches = append((*parent)[i].Branches, csafTypes.Branch{
				Category: "product_version",
				Name:     fmt.Sprintf("%s/%s", branch, version),
				Product:  &csafTypes.FullProductName{Name: branch, ProductID: pid},
			})
			cov[coveredBy] = append(cov[coveredBy], pid)
			defined[pid] = struct{}{}
		}
	}
	return nil
}

// resolveReferences rewrites the product references of doc to product_ids,
// the way CSAF has them. Fortinet scopes scores[].products and
// remediations[].product_ids by the product branch name ("FortiWeb")
// instead: a branch carries no product, so the name is not a product_id at
// all, and it stands for every leaf it covers (see coverage). Every such
// reference in the corpus (546 CSAF advisories as of 2026-09) is spelled that
// way, no branch name equals a product_id, and no remediation or threat is
// scoped by group_ids, nor any threat by product_ids. Every score and
// remediation is scoped: CSAF requires scores[].products, and
// remediations[].product_ids or group_ids.
//
// Anything else hard-errors — a reference that is not a branch name, a leaf
// product_id included, an unscoped score or remediation, and a scoped threat —
// since it would be a change of Fortinet's format, to route deliberately
// rather than guess at.
func resolveReferences(doc *csafTypes.CSAF, cov coverage) error {
	for i := range doc.Vulnerabilities {
		v := &doc.Vulnerabilities[i]
		for j := range v.Scores {
			if len(v.Scores[j].Products) == 0 {
				return errors.Errorf("unexpected unscoped score of %q", v.CVE)
			}
			pids, err := cov.expand(v.Scores[j].Products)
			if err != nil {
				return errors.Wrapf(err, "scores.products of %q", v.CVE)
			}
			v.Scores[j].Products = pids
		}
		for j := range v.Remediations {
			if len(v.Remediations[j].GroupIDs) > 0 {
				return errors.Errorf("unexpected remediations.group_ids %q of %q", v.Remediations[j].GroupIDs, v.CVE)
			}
			if len(v.Remediations[j].ProductIDs) == 0 {
				return errors.Errorf("unexpected unscoped remediation of %q", v.CVE)
			}
			pids, err := cov.expand(v.Remediations[j].ProductIDs)
			if err != nil {
				return errors.Wrapf(err, "remediations.product_ids of %q", v.CVE)
			}
			v.Remediations[j].ProductIDs = pids
		}
		for _, t := range v.Threats {
			if len(t.ProductIDs) > 0 || len(t.GroupIDs) > 0 {
				return errors.Errorf("unexpected scoped threat of %q (product_ids: %q, group_ids: %q)", v.CVE, t.ProductIDs, t.GroupIDs)
			}
		}
	}
	return nil
}

// expand returns the product_ids the branches a reference list names cover,
// each once, in order. It hard-errors on a reference that is not a branch
// name.
func (cov coverage) expand(ids []csafTypes.ProductID) ([]csafTypes.ProductID, error) {
	var pids []csafTypes.ProductID
	for _, id := range ids {
		covered, ok := cov[string(id)]
		if !ok {
			return nil, errors.Errorf("unexpected product reference %q. expected: a product branch name", string(id))
		}
		for _, pid := range covered {
			if !slices.Contains(pids, pid) {
				pids = append(pids, pid)
			}
		}
	}
	return pids, nil
}

// treeFixes lists the advisories whose product tree, or the product_status
// lists referencing it, the published advisory gets wrong, each repair
// written out in full as published and as read, from the advisory's own
// vendor_fix text. Most file the leaves of "<product> Cloud" under
// "<product>" with "Cloud" dropped, which leaves the Cloud product undetected
// and, where the ranges coincide, two leaves with one product_id.
var treeFixes = map[string]treeFix{
	// The vendor_fix text lists "FortiManager Cloud 7.4" first; the first FortiManager
	// leaf is that Cloud range with "Cloud" dropped.
	"FG-IR-24-091": {
		branches: []branchFix{{
			name: "FortiManager",
			leaves: []string{
				"FortiManager/>=7.4.1|<=7.4.2",
				"FortiManager/ 7.6 all versions",
				"FortiManager/>=7.4.0|<=7.4.2",
				"FortiManager/ 7.2 all versions",
				"FortiManager/ 7.0 all versions",
			},
			to: map[int]leafTarget{
				0: {product: "FortiManager Cloud", version: ">=7.4.1|<=7.4.2"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiManager >=7.4.1|<=7.4.2", "FortiManager >=7.4.0|<=7.4.2"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud >=7.4.1|<=7.4.2"},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager/ 7.6 all versions", "FortiManager-7.4.3", "FortiManager/ 7.2 all versions", "FortiManager/ 7.0 all versions"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud-7.4.3"},
				},
			},
		},
	},
	// Same shape as FG-IR-24-091.
	"FG-IR-24-106": {
		branches: []branchFix{{
			name: "FortiManager",
			leaves: []string{
				"FortiManager/>=7.4.1|<=7.4.2",
				"FortiManager/ 7.6 all versions",
				"FortiManager/>=7.4.0|<=7.4.2",
				"FortiManager/ 7.2 all versions",
				"FortiManager/ 7.0 all versions",
			},
			to: map[int]leafTarget{
				0: {product: "FortiManager Cloud", version: ">=7.4.1|<=7.4.2"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiManager >=7.4.1|<=7.4.2", "FortiManager >=7.4.0|<=7.4.2"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud >=7.4.1|<=7.4.2"},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager/ 7.6 all versions", "FortiManager-7.4.3", "FortiManager/ 7.2 all versions", "FortiManager/ 7.0 all versions"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud-7.4.3"},
				},
			},
		},
	},
	// The vendor_fix text lists FortiClientEMS Cloud 7.4/7.2/7.0 before FortiClientEMS
	// 7.4/7.2/7.0, and the leaves follow that order; only the first keeps
	// "Cloud", so the Cloud 7.2/7.0 leaves collide with the on-premise ones.
	"FG-IR-24-123": {
		branches: []branchFix{{
			name: "FortiClientEMS",
			leaves: []string{
				"FortiClientEMS/ Cloud 7.4 all versions",
				"FortiClientEMS/>=7.2.0|<=7.2.4",
				"FortiClientEMS/>=7.0.0|<=7.0.12",
				"FortiClientEMS/ 7.4 all versions",
				"FortiClientEMS/>=7.2.0|<=7.2.4",
				"FortiClientEMS/>=7.0.0|<=7.0.12",
			},
			to: map[int]leafTarget{
				0: {product: "FortiClientEMS Cloud", version: "7.4 all versions"},
				1: {product: "FortiClientEMS Cloud", version: ">=7.2.0|<=7.2.4"},
				2: {product: "FortiClientEMS Cloud", version: ">=7.0.0|<=7.0.12"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiClientEMS >=7.2.0|<=7.2.4", "FortiClientEMS >=7.0.0|<=7.0.12", "FortiClientEMS >=7.2.0|<=7.2.4", "FortiClientEMS >=7.0.0|<=7.0.12"},
				to: map[int]statusTarget{
					0: {productID: "FortiClientEMS Cloud >=7.2.0|<=7.2.4"},
					1: {productID: "FortiClientEMS Cloud >=7.0.0|<=7.0.12"},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiClientEMS/ Cloud 7.4 all versions", "FortiClientEMS-7.2.5", "FortiClientEMS-7.0.13", "FortiClientEMS/ 7.4 all versions", "FortiClientEMS-7.2.5", "FortiClientEMS-7.0.13"},
				to: map[int]statusTarget{
					0: {productID: "FortiClientEMS Cloud 7.4 all versions"},
					1: {productID: "FortiClientEMS Cloud-7.2.5"},
					2: {productID: "FortiClientEMS Cloud-7.0.13"},
				},
			},
		},
	},
	// Two leaves carry "cloud" in the version. Two more are Cloud with the word
	// dropped even from the vendor_fix text: >=7.4.1|<=7.4.2 and >=7.2.1|<=7.2.6
	// (fixed in 7.2.7) repeat the FortiAnalyzer Cloud ranges and fix of the same
	// advisory, beside the on-premise >=7.4.0|<=7.4.2 and >=7.2.0|<=7.2.5 (7.2.6).
	"FG-IR-24-125": {
		branches: []branchFix{{
			name: "FortiManager",
			leaves: []string{
				"FortiManager/cloud 7.0 all versions",
				"FortiManager/cloud 6.4 all versions",
				"FortiManager/>=7.4.0|<=7.4.2",
				"FortiManager/>=7.4.1|<=7.4.2",
				"FortiManager/>=7.2.0|<=7.2.5",
				"FortiManager/>=7.2.1|<=7.2.6",
				"FortiManager/7.0 all versions",
				"FortiManager/6.4 all versions",
				"FortiManager/6.2 all versions",
				"FortiManager/6.0 all versions",
			},
			to: map[int]leafTarget{
				0: {product: "FortiManager Cloud", version: "7.0 all versions"},
				1: {product: "FortiManager Cloud", version: "6.4 all versions"},
				3: {product: "FortiManager Cloud", version: ">=7.4.1|<=7.4.2"},
				5: {product: "FortiManager Cloud", version: ">=7.2.1|<=7.2.6"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiManager cloud 7.0 all versions", "FortiManager cloud 6.4 all versions", "FortiManager >=7.4.0|<=7.4.2", "FortiManager >=7.4.1|<=7.4.2", "FortiManager >=7.2.0|<=7.2.5", "FortiManager >=7.2.1|<=7.2.6", "FortiManager 7.0 all versions", "FortiManager 6.4 all versions", "FortiManager 6.2 all versions", "FortiManager 6.0 all versions"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud 7.0 all versions"},
					1: {productID: "FortiManager Cloud 6.4 all versions"},
					3: {productID: "FortiManager Cloud >=7.4.1|<=7.4.2"},
					5: {productID: "FortiManager Cloud >=7.2.1|<=7.2.6"},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager-7.4.3", "FortiManager-7.2.6", "FortiManager-7.2.7"},
				to: map[int]statusTarget{
					1: {productID: "FortiManager Cloud-7.4.3"},
					3: {productID: "FortiManager Cloud-7.2.7"},
				},
			},
		},
	},
	// The vendor_fix text lists FortiManager Cloud 7.4/7.2/7.0 first; the first
	// three FortiManager leaves are those Cloud ranges with "Cloud" dropped.
	"FG-IR-24-127": {
		branches: []branchFix{{
			name: "FortiManager",
			leaves: []string{
				"FortiManager/>=7.4.1|<=7.4.3",
				"FortiManager/>=7.2.1|<=7.2.5",
				"FortiManager/7.0 all versions",
				"FortiManager/ 7.6 all versions",
				"FortiManager/>=7.4.0|<=7.4.3",
				"FortiManager/>=7.2.0|<=7.2.5",
				"FortiManager/7.0 all versions",
				"FortiManager/6.4 all versions",
			},
			to: map[int]leafTarget{
				0: {product: "FortiManager Cloud", version: ">=7.4.1|<=7.4.3"},
				1: {product: "FortiManager Cloud", version: ">=7.2.1|<=7.2.5"},
				2: {product: "FortiManager Cloud", version: "7.0 all versions"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiManager >=7.4.1|<=7.4.3", "FortiManager >=7.2.1|<=7.2.5", "FortiManager 7.0 all versions", "FortiManager >=7.4.0|<=7.4.3", "FortiManager >=7.2.0|<=7.2.5", "FortiManager 7.0 all versions", "FortiManager 6.4 all versions"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud >=7.4.1|<=7.4.3"},
					1: {productID: "FortiManager Cloud >=7.2.1|<=7.2.5"},
					2: {productID: "FortiManager Cloud 7.0 all versions"},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.4", "FortiManager-7.2.7", "FortiManager/ 7.6 all versions", "FortiManager-7.4.4", "FortiManager-7.2.6"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud-7.4.4"},
					1: {productID: "FortiManager Cloud-7.2.7"},
				},
			},
		},
	},
	// Same shape as FG-IR-24-127.
	"FG-IR-24-135": {
		branches: []branchFix{{
			name: "FortiManager",
			leaves: []string{
				"FortiManager/>=7.4.1|<=7.4.2",
				"FortiManager/>=7.2.1|<=7.2.5",
				"FortiManager/>=7.0.1|<=7.0.12",
				"FortiManager/ 7.6 all versions",
				"FortiManager/>=7.4.0|<=7.4.2",
				"FortiManager/>=7.2.0|<=7.2.5",
				"FortiManager/>=7.0.0|<=7.0.12",
				"FortiManager/>=6.4.0|<=6.4.14",
			},
			to: map[int]leafTarget{
				0: {product: "FortiManager Cloud", version: ">=7.4.1|<=7.4.2"},
				1: {product: "FortiManager Cloud", version: ">=7.2.1|<=7.2.5"},
				2: {product: "FortiManager Cloud", version: ">=7.0.1|<=7.0.12"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiManager >=7.4.1|<=7.4.2", "FortiManager >=7.2.1|<=7.2.5", "FortiManager >=7.0.1|<=7.0.12", "FortiManager >=7.4.0|<=7.4.2", "FortiManager >=7.2.0|<=7.2.5", "FortiManager >=7.0.0|<=7.0.12", "FortiManager >=6.4.0|<=6.4.14"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud >=7.4.1|<=7.4.2"},
					1: {productID: "FortiManager Cloud >=7.2.1|<=7.2.5"},
					2: {productID: "FortiManager Cloud >=7.0.1|<=7.0.12"},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager-7.2.7", "FortiManager-7.0.13", "FortiManager/ 7.6 all versions", "FortiManager-7.4.3", "FortiManager-7.2.6", "FortiManager-7.0.13", "FortiManager-6.4.15"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud-7.4.3"},
					1: {productID: "FortiManager Cloud-7.2.7"},
					2: {productID: "FortiManager Cloud-7.0.13"},
				},
			},
		},
	},
	// The FortiAnalyzer vendor_fix text lists "FortiAnalyzer Cloud 7.4" first; the
	// first FortiAnalyzer leaf is that Cloud range with "Cloud" dropped.
	"FG-IR-24-221": {
		branches: []branchFix{{
			name: "FortiAnalyzer",
			leaves: []string{
				"FortiAnalyzer/>=7.4.1|<=7.4.3",
				"FortiAnalyzer/>=7.6.0|<=7.6.1",
				"FortiAnalyzer/>=7.4.1|<=7.4.3",
				"FortiAnalyzer/ 7.2 all versions",
				"FortiAnalyzer/ 7.0 all versions",
			},
			to: map[int]leafTarget{
				0: {product: "FortiAnalyzer Cloud", version: ">=7.4.1|<=7.4.3"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiAnalyzer >=7.4.1|<=7.4.3", "FortiAnalyzer >=7.6.0|<=7.6.1", "FortiAnalyzer >=7.4.1|<=7.4.3"},
				to: map[int]statusTarget{
					0: {productID: "FortiAnalyzer Cloud >=7.4.1|<=7.4.3"},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiAnalyzer-7.4.4", "FortiAnalyzer-7.6.2", "FortiAnalyzer-7.4.4", "FortiAnalyzer/ 7.2 all versions", "FortiAnalyzer/ 7.0 all versions"},
				to: map[int]statusTarget{
					0: {productID: "FortiAnalyzer Cloud-7.4.4"},
				},
			},
		},
	},
	// Same shape as FG-IR-24-091.
	"FG-IR-24-222": {
		branches: []branchFix{{
			name: "FortiManager",
			leaves: []string{
				"FortiManager/>=7.4.1|<=7.4.3",
				"FortiManager/ 7.6 all versions",
				"FortiManager/>=7.4.1|<=7.4.3",
				"FortiManager/ 7.2 all versions",
				"FortiManager/ 7.0 all versions",
			},
			to: map[int]leafTarget{
				0: {product: "FortiManager Cloud", version: ">=7.4.1|<=7.4.3"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiManager >=7.4.1|<=7.4.3", "FortiManager >=7.4.1|<=7.4.3"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud >=7.4.1|<=7.4.3"},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.4", "FortiManager/ 7.6 all versions", "FortiManager-7.4.4", "FortiManager/ 7.2 all versions", "FortiManager/ 7.0 all versions"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud-7.4.4"},
				},
			},
		},
	},
	// Same shape as FG-IR-24-127 (Cloud 7.6/7.4/7.2).
	"FG-IR-24-463": {
		branches: []branchFix{{
			name: "FortiManager",
			leaves: []string{
				"FortiManager/>=7.6.0|<=7.6.1",
				"FortiManager/>=7.4.0|<=7.4.4",
				"FortiManager/>=7.2.2|<=7.2.7",
				"FortiManager/>=7.6.0|<=7.6.1",
				"FortiManager/>=7.4.0|<=7.4.5",
				"FortiManager/>=7.2.1|<=7.2.8",
				"FortiManager/ 7.0 all versions",
			},
			to: map[int]leafTarget{
				0: {product: "FortiManager Cloud", version: ">=7.6.0|<=7.6.1"},
				1: {product: "FortiManager Cloud", version: ">=7.4.0|<=7.4.4"},
				2: {product: "FortiManager Cloud", version: ">=7.2.2|<=7.2.7"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiManager >=7.6.0|<=7.6.1", "FortiManager >=7.4.0|<=7.4.4", "FortiManager >=7.2.2|<=7.2.7", "FortiManager >=7.6.0|<=7.6.1", "FortiManager >=7.4.0|<=7.4.5", "FortiManager >=7.2.1|<=7.2.8"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud >=7.6.0|<=7.6.1"},
					1: {productID: "FortiManager Cloud >=7.4.0|<=7.4.4"},
					2: {productID: "FortiManager Cloud >=7.2.2|<=7.2.7"},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.6.2", "FortiManager-7.4.5", "FortiManager-7.2.8", "FortiManager-7.6.2", "FortiManager-7.4.6", "FortiManager-7.2.9", "FortiManager/ 7.0 all versions"},
				to: map[int]statusTarget{
					0: {productID: "FortiManager Cloud-7.6.2"},
					1: {productID: "FortiManager Cloud-7.4.5"},
					2: {productID: "FortiManager Cloud-7.2.8"},
				},
			},
		},
	},
	// The vendor_fix text names FortiSandbox Cloud 24 and 23; both leaves lost the
	// train and read "all versions".
	"FG-IR-26-136": {
		branches: []branchFix{{
			name: "FortiSandbox Cloud",
			leaves: []string{
				"FortiSandbox Cloud/all versions",
				"FortiSandbox Cloud/all versions",
				"FortiSandbox Cloud/>=5.0.2|<=5.0.5",
			},
			to: map[int]leafTarget{
				0: {product: "FortiSandbox Cloud", version: "24 all versions"},
				1: {product: "FortiSandbox Cloud", version: "23 all versions"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiSandbox Cloud all versions", "FortiSandbox Cloud all versions", "FortiSandbox Cloud >=5.0.2|<=5.0.5"},
				to: map[int]statusTarget{
					0: {productID: "FortiSandbox Cloud 24 all versions"},
					1: {productID: "FortiSandbox Cloud 23 all versions"},
				},
			},
		},
	},

	// The fix is FortiSOAR File Content Extraction Connector 1.3.1, a separate
	// component; the known_not_affected entries are that text cut short, and
	// no FortiSOAR version stands behind them.
	"FG-IR-26-116": {
		statuses: []statusFix{
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiSOAR PaaS-f", "FortiSOAR PaaS-f", "FortiSOAR PaaS-f", "FortiSOAR PaaS-f"},
				to: map[int]statusTarget{
					0: {drop: true},
					1: {drop: true},
					2: {drop: true},
					3: {drop: true},
				},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiSOAR on-premise-f", "FortiSOAR on-premise-f", "FortiSOAR on-premise-f", "FortiSOAR on-premise-f"},
				to: map[int]statusTarget{
					0: {drop: true},
					1: {drop: true},
					2: {drop: true},
					3: {drop: true},
				},
			},
		},
	},
	// The upcoming fixed release, spelled with a stray "version".
	"FG-IR-25-512": {
		statuses: []statusFix{
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiWeb/ 8.0 all versions", "FortiWeb-7.6.5", "FortiWeb-7.4.9", "FortiWeb-upcoming version 7.2.12"},
				to: map[int]statusTarget{
					3: {productID: "FortiWeb-upcoming 7.2.12"},
				},
			},
		},
	},
	// The OpenSSL advisory files every product it rules out under the FortiNAC-F
	// branch ("FortiNAC-F/FortiOS all versions"). Each goes to its own product,
	// spelled as the product table has it; "FortiSOAR" covers both FortiSOAR
	// products, which share one CPE, so it goes to "FortiSOAR on-premise".
	"FG-IR-26-076": {
		branches: []branchFix{{
			name: "FortiNAC-F",
			leaves: []string{
				"FortiNAC-F/FortiWeb Manager all versions",
				"FortiNAC-F/FortiWeb all versions",
				"FortiNAC-F/FortiVoice all versions",
				"FortiNAC-F/FortiTester all versions",
				"FortiNAC-F/FortiSwitch all versions",
				"FortiNAC-F/FortiSandbox all versions",
				"FortiNAC-F/FortiSOAR all versions",
				"FortiNAC-F/FortiSIEM all versions",
				"FortiNAC-F/FortiRecorder all versions",
				"FortiNAC-F/FortiProxy all versions",
				"FortiNAC-F/FortiPortal all versions",
				"FortiNAC-F/FortiOS all versions",
				"FortiNAC-F/ all versions",
				"FortiNAC-F/FortiNAC all versions",
				"FortiNAC-F/FortiManager all versions",
				"FortiNAC-F/FortiMail all versions",
				"FortiNAC-F/FortiExtender all versions",
				"FortiNAC-F/FortiDDoS all versions",
				"FortiNAC-F/FortiConverter all versions",
				"FortiNAC-F/FortiCloud all versions",
				"FortiNAC-F/FortiClient iOS all versions",
				"FortiNAC-F/FortiClient Windows all versions",
				"FortiNAC-F/FortiClient MacOS all versions",
				"FortiNAC-F/FortiClient Linux all versions",
				"FortiNAC-F/FortiClient EMS all versions",
				"FortiNAC-F/FortiClient Android all versions",
				"FortiNAC-F/FortiAuthenticator all versions",
				"FortiNAC-F/FortiAnalyzer all versions",
				"FortiNAC-F/FortiAP-W2 all versions",
				"FortiNAC-F/FortiAP-U all versions",
				"FortiNAC-F/FortiAP all versions",
				"FortiNAC-F/FortiADC Manager all versions",
				"FortiNAC-F/FortiADC all versions",
			},
			to: map[int]leafTarget{
				0:  {product: "FortiWebManager", version: "all versions"},
				1:  {product: "FortiWeb", version: "all versions"},
				2:  {product: "FortiVoice", version: "all versions"},
				3:  {product: "FortiTester", version: "all versions"},
				4:  {product: "FortiSwitch", version: "all versions"},
				5:  {product: "FortiSandbox", version: "all versions"},
				6:  {product: "FortiSOAR on-premise", version: "all versions"},
				7:  {product: "FortiSIEM", version: "all versions"},
				8:  {product: "FortiRecorder", version: "all versions"},
				9:  {product: "FortiProxy", version: "all versions"},
				10: {product: "FortiPortal", version: "all versions"},
				11: {product: "FortiOS", version: "all versions"},
				13: {product: "FortiNAC", version: "all versions"},
				14: {product: "FortiManager", version: "all versions"},
				15: {product: "FortiMail", version: "all versions"},
				16: {product: "FortiExtender", version: "all versions"},
				17: {product: "FortiDDoS", version: "all versions"},
				18: {product: "FortiConverter", version: "all versions"},
				19: {product: "FortiCloud", version: "all versions"},
				20: {product: "FortiClientiOS", version: "all versions"},
				21: {product: "FortiClientWindows", version: "all versions"},
				22: {product: "FortiClientMac", version: "all versions"},
				23: {product: "FortiClientLinux", version: "all versions"},
				24: {product: "FortiClientEMS", version: "all versions"},
				25: {product: "FortiClientAndroid", version: "all versions"},
				26: {product: "FortiAuthenticator", version: "all versions"},
				27: {product: "FortiAnalyzer", version: "all versions"},
				28: {product: "FortiAP-W2", version: "all versions"},
				29: {product: "FortiAP-U", version: "all versions"},
				30: {product: "FortiAP", version: "all versions"},
				31: {product: "FortiADCManager", version: "all versions"},
				32: {product: "FortiADC", version: "all versions"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiNAC-F/FortiWeb Manager all versions", "FortiNAC-F/FortiWeb all versions", "FortiNAC-F/FortiVoice all versions", "FortiNAC-F/FortiTester all versions", "FortiNAC-F/FortiSwitch all versions", "FortiNAC-F/FortiSandbox all versions", "FortiNAC-F/FortiSOAR all versions", "FortiNAC-F/FortiSIEM all versions", "FortiNAC-F/FortiRecorder all versions", "FortiNAC-F/FortiProxy all versions", "FortiNAC-F/FortiPortal all versions", "FortiNAC-F/FortiOS all versions", "FortiNAC-F/ all versions", "FortiNAC-F/FortiNAC all versions", "FortiNAC-F/FortiManager all versions", "FortiNAC-F/FortiMail all versions", "FortiNAC-F/FortiExtender all versions", "FortiNAC-F/FortiDDoS all versions", "FortiNAC-F/FortiConverter all versions", "FortiNAC-F/FortiCloud all versions", "FortiNAC-F/FortiClient iOS all versions", "FortiNAC-F/FortiClient Windows all versions", "FortiNAC-F/FortiClient MacOS all versions", "FortiNAC-F/FortiClient Linux all versions", "FortiNAC-F/FortiClient EMS all versions", "FortiNAC-F/FortiClient Android all versions", "FortiNAC-F/FortiAuthenticator all versions", "FortiNAC-F/FortiAnalyzer all versions", "FortiNAC-F/FortiAP-W2 all versions", "FortiNAC-F/FortiAP-U all versions", "FortiNAC-F/FortiAP all versions", "FortiNAC-F/FortiADC Manager all versions", "FortiNAC-F/FortiADC all versions"},
				to: map[int]statusTarget{
					0:  {productID: "FortiWebManager all versions"},
					1:  {productID: "FortiWeb all versions"},
					2:  {productID: "FortiVoice all versions"},
					3:  {productID: "FortiTester all versions"},
					4:  {productID: "FortiSwitch all versions"},
					5:  {productID: "FortiSandbox all versions"},
					6:  {productID: "FortiSOAR on-premise all versions"},
					7:  {productID: "FortiSIEM all versions"},
					8:  {productID: "FortiRecorder all versions"},
					9:  {productID: "FortiProxy all versions"},
					10: {productID: "FortiPortal all versions"},
					11: {productID: "FortiOS all versions"},
					13: {productID: "FortiNAC all versions"},
					14: {productID: "FortiManager all versions"},
					15: {productID: "FortiMail all versions"},
					16: {productID: "FortiExtender all versions"},
					17: {productID: "FortiDDoS all versions"},
					18: {productID: "FortiConverter all versions"},
					19: {productID: "FortiCloud all versions"},
					20: {productID: "FortiClientiOS all versions"},
					21: {productID: "FortiClientWindows all versions"},
					22: {productID: "FortiClientMac all versions"},
					23: {productID: "FortiClientLinux all versions"},
					24: {productID: "FortiClientEMS all versions"},
					25: {productID: "FortiClientAndroid all versions"},
					26: {productID: "FortiAuthenticator all versions"},
					27: {productID: "FortiAnalyzer all versions"},
					28: {productID: "FortiAP-W2 all versions"},
					29: {productID: "FortiAP-U all versions"},
					30: {productID: "FortiAP all versions"},
					31: {productID: "FortiADCManager all versions"},
					32: {productID: "FortiADC all versions"},
				},
			},
		},
	},
	// The vendor_fix text lists "FortiSIEM Cloud: Not Applicable" first; the first
	// FortiSIEM leaf is FortiSIEM Cloud with "Cloud" moved into the version.
	"FG-IR-25-772": {
		branches: []branchFix{{
			name: "FortiSIEM",
			leaves: []string{
				"FortiSIEM/ Cloud all versions",
				"FortiSIEM/ 7.5 all versions",
				"FortiSIEM/7.4.0",
				"FortiSIEM/>=7.3.0|<=7.3.4",
				"FortiSIEM/>=7.2.0|<=7.2.6",
				"FortiSIEM/>=7.1.0|<=7.1.8",
				"FortiSIEM/>=7.0.0|<=7.0.4",
				"FortiSIEM/>=6.7.0|<=6.7.10",
			},
			to: map[int]leafTarget{
				0: {product: "FortiSIEM Cloud", version: "all versions"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiSIEM/ Cloud all versions", "FortiSIEM/ 7.5 all versions", "FortiSIEM-7.4.1", "FortiSIEM-7.3.5", "FortiSIEM-7.2.7", "FortiSIEM-7.1.9"},
				to: map[int]statusTarget{
					0: {productID: "FortiSIEM Cloud all versions"},
				},
			},
		},
	},
	// A free-text remark was left on the leaf when the advisory table was
	// converted ("6.0 all versions (need to be authenticated to provoke a
	// crash)"). It qualifies how the train is affected, not which versions are:
	// NVD treats the whole train as affected too, and a criterion has no field
	// for it.
	"FG-IR-22-086": {
		branches: []branchFix{{
			name: "FortiOS",
			leaves: []string{
				"FortiOS/7.2.0",
				"FortiOS/>=7.0.0|<=7.0.5",
				"FortiOS/>=6.4.0|<=6.4.9",
				"FortiOS/>=6.2.0|<=6.2.10",
				"FortiOS/6.0 all versions (need to be authenticated to provoke a crash)",
			},
			to: map[int]leafTarget{
				4: {product: "FortiOS", version: "6.0 all versions"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiOS 7.2.0", "FortiOS >=7.0.0|<=7.0.5", "FortiOS >=6.4.0|<=6.4.9", "FortiOS >=6.2.0|<=6.2.10", "FortiOS 6.0 all versions (need to be authenticated to provoke a crash)"},
				to: map[int]statusTarget{
					4: {productID: "FortiOS 6.0 all versions"},
				},
			},
		},
	},
	// Same as FG-IR-22-086, on five trains ("5.0 all versions (special note for
	// fortios in additional note section)"); NVD treats the trains as affected
	// (CVE-2023-25610: fortios 5.0.0 to 6.2.13).
	"FG-IR-23-001": {
		branches: []branchFix{{
			name: "FortiOS",
			leaves: []string{
				"FortiOS/>=7.2.0|<=7.2.3",
				"FortiOS/>=7.0.0|<=7.0.9",
				"FortiOS/>=6.4.0|<=6.4.11",
				"FortiOS/>=6.2.0|<=6.2.12",
				"FortiOS/6.0 all versions (special note for fortios in additional note section)",
				"FortiOS/5.6 all versions (special note for fortios in additional note section)",
				"FortiOS/5.4 all versions (special note for fortios in additional note section)",
				"FortiOS/5.2 all versions (special note for fortios in additional note section)",
				"FortiOS/5.0 all versions (special note for fortios in additional note section)",
			},
			to: map[int]leafTarget{
				4: {product: "FortiOS", version: "6.0 all versions"},
				5: {product: "FortiOS", version: "5.6 all versions"},
				6: {product: "FortiOS", version: "5.4 all versions"},
				7: {product: "FortiOS", version: "5.2 all versions"},
				8: {product: "FortiOS", version: "5.0 all versions"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiOS >=7.2.0|<=7.2.3", "FortiOS >=7.0.0|<=7.0.9", "FortiOS >=6.4.0|<=6.4.11", "FortiOS >=6.2.0|<=6.2.12", "FortiOS 6.0 all versions (special note for fortios in additional note section)", "FortiOS 5.6 all versions (special note for fortios in additional note section)", "FortiOS 5.4 all versions (special note for fortios in additional note section)", "FortiOS 5.2 all versions (special note for fortios in additional note section)", "FortiOS 5.0 all versions (special note for fortios in additional note section)"},
				to: map[int]statusTarget{
					4: {productID: "FortiOS 6.0 all versions"},
					5: {productID: "FortiOS 5.6 all versions"},
					6: {productID: "FortiOS 5.4 all versions"},
					7: {productID: "FortiOS 5.2 all versions"},
					8: {productID: "FortiOS 5.0 all versions"},
				},
			},
		},
	},
	// The advisory table reads "7.2.0 though 7.2.7", a typo of "through", so the
	// conversion that turns "<lo> through <hi>" into ">=<lo>|<=<hi>" (as it did
	// for FortiAnalyzer and FortiManager in the same advisory) left it as text.
	// NVD reads it the same way (fortianalyzer_big_data 7.2.0 ≤ v ≤ 7.2.7 for
	// CVE-2024-31496).
	"FG-IR-24-098": {
		branches: []branchFix{{
			name: "FortiAnalyzer-BigData",
			leaves: []string{
				"FortiAnalyzer-BigData/7.4.0",
				"FortiAnalyzer-BigData/7.2.0 though 7.2.7",
				"FortiAnalyzer-BigData/7.0 all versions",
				"FortiAnalyzer-BigData/6.4 all versions",
				"FortiAnalyzer-BigData/6.2 all versions",
			},
			to: map[int]leafTarget{
				1: {product: "FortiAnalyzer-BigData", version: ">=7.2.0|<=7.2.7"},
			},
		}},
		statuses: []statusFix{
			{
				list: knownAffected,
				from: []csafTypes.ProductID{"FortiAnalyzer-BigData 7.4.0", "FortiAnalyzer-BigData 7.2.0 though 7.2.7", "FortiAnalyzer-BigData 7.0 all versions", "FortiAnalyzer-BigData 6.4 all versions", "FortiAnalyzer-BigData 6.2 all versions"},
				to: map[int]statusTarget{
					1: {productID: "FortiAnalyzer-BigData >=7.2.0|<=7.2.7"},
				},
			},
		},
	},
}
