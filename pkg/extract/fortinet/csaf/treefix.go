package csaf

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/pkg/errors"

	csafTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/csaf"
)

// fixProductTree repairs the product tree of doc, and the product_status lists
// that reference it, where the published advisory gets them wrong, so the
// rest of the extractor reads a tree that says what the advisory means. It
// runs on the document as fetched, before anything else reads it.
//
// First the advisory-bound repairs of treeFixes, each written out in full and
// hard-erroring when the advisory no longer matches it. Then every
// known_not_affected product_id the tree does not define is defined (see
// defineNotAffected).
func fixProductTree(doc *csafTypes.CSAF) error {
	if fix, ok := treeFixes[doc.Document.Tracking.ID]; ok {
		if err := fix.apply(doc); err != nil {
			return errors.Wrapf(err, "apply the tree fix of %s", doc.Document.Tracking.ID)
		}
	}
	if err := defineNotAffected(doc); err != nil {
		return errors.Wrap(err, "define known_not_affected products")
	}
	return nil
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
// to what it is. A leaf moved to another product goes to a sibling branch of
// that name, which must not exist in the published tree: a reference naming
// the original branch is extended to name the new one too (it was written for
// the leaves under the original), which would wrongly also cover a branch that
// already had leaves of its own.
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

// statusFix replaces a product_status list written out in full as published
// with the list it is read as, in every vulnerability object carrying it.
// Positions matter where a product_id repeats: a list names the Cloud and the
// on-premise leaf with one product_id in the same order as the tree.
type statusFix struct {
	list statusList
	from []csafTypes.ProductID
	to   []csafTypes.ProductID
}

type statusList int

const (
	knownAffected statusList = iota
	knownNotAffected
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
		return nil, errors.Errorf("unexpected product_status list. expected: %q, actual: %d", []string{"known_affected", "known_not_affected"}, l)
	}
}

func (f treeFix) apply(doc *csafTypes.CSAF) error {
	for _, bf := range f.branches {
		if err := bf.apply(doc); err != nil {
			return errors.Wrapf(err, "branch %q", bf.name)
		}
	}
	for _, sf := range f.statuses {
		n := 0
		for i := range doc.Vulnerabilities {
			l, err := sf.list.of(&doc.Vulnerabilities[i])
			if err != nil {
				return errors.Wrap(err, "select product_status list")
			}
			if slices.Equal(*l, sf.from) {
				*l = slices.Clone(sf.to)
				n++
			}
		}
		if n == 0 {
			return errors.Errorf("no vulnerability has the product_status list %q; the tree fix is stale", sf.from)
		}
	}
	return nil
}

func (bf branchFix) apply(doc *csafTypes.CSAF) error {
	parent, i, err := findProductBranch(doc.ProductTree.Branches, bf.name)
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

	var (
		kept  []csafTypes.Branch
		moved = make(map[string][]csafTypes.Branch)
	)
	for j, leaf := range branch.Branches {
		t, ok := bf.to[j]
		if !ok {
			kept = append(kept, leaf)
			continue
		}
		if leaf.Product == nil {
			return errors.Errorf("leaf %q has no product", leaf.Name)
		}
		leaf.Name = fmt.Sprintf("%s/%s", t.product, t.version)
		leaf.Product.Name = t.product
		leaf.Product.ProductID = csafTypes.ProductID(fmt.Sprintf("%s %s", t.product, t.version))
		if t.product == bf.name {
			kept = append(kept, leaf)
			continue
		}
		moved[t.product] = append(moved[t.product], leaf)
	}
	branch.Branches = kept

	for _, product := range slices.Sorted(maps.Keys(moved)) {
		if _, _, err := findProductBranch(doc.ProductTree.Branches, product); err == nil {
			return errors.Errorf("branch %q to move leaves to already exists", product)
		}
		*parent = append(*parent, csafTypes.Branch{Category: "product", Name: product, Branches: moved[product]})
		extendReferences(doc, bf.name, product)
	}
	return nil
}

// findProductBranch returns the slice holding the one product branch named
// name, and its index there. It errors when there is none, or more than one.
func findProductBranch(bs []csafTypes.Branch, name string) (*[]csafTypes.Branch, int, error) {
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
	walk(&bs)
	switch n {
	case 0:
		return nil, 0, errors.Errorf("no product branch %q", name)
	case 1:
		return found, at, nil
	default:
		return nil, 0, errors.Errorf("%d product branches %q", n, name)
	}
}

// extendReferences adds to to every score, threat and remediation reference
// list naming from, so the leaves moved from branch from to branch to stay
// covered by what was written for them.
func extendReferences(doc *csafTypes.CSAF, from, to string) {
	extend := func(ids []csafTypes.ProductID) []csafTypes.ProductID {
		if slices.Contains(ids, csafTypes.ProductID(from)) && !slices.Contains(ids, csafTypes.ProductID(to)) {
			return append(ids, csafTypes.ProductID(to))
		}
		return ids
	}
	for i := range doc.Vulnerabilities {
		v := &doc.Vulnerabilities[i]
		for j := range v.Scores {
			v.Scores[j].Products = extend(v.Scores[j].Products)
		}
		for j := range v.Threats {
			v.Threats[j].ProductIDs = extend(v.Threats[j].ProductIDs)
		}
		for j := range v.Remediations {
			v.Remediations[j].ProductIDs = extend(v.Remediations[j].ProductIDs)
		}
	}
}

// notAffectedVersion returns the version that a known_not_affected product_id
// the tree leaves undefined names under branch, in one of the two spellings
// Fortinet uses: "<branch>-<version>", the fixed release ("FortiOS-7.4.8"),
// and "<branch>-upcoming <version>", the fixed release yet to ship
// ("FortiWeb-upcoming  7.2.13"; two spaces, one in FG-IR-23-385), left
// unchanged once it ships. Anything else reports false, so a new spelling is
// added here or repaired in treeFixes by hand rather than read by shape. The
// branch is given, not parsed, since product names carry hyphens too
// ("FortiNAC-F").
func notAffectedVersion(pid csafTypes.ProductID, branch string) (string, bool) {
	rest, ok := strings.CutPrefix(string(pid), fmt.Sprintf("%s-", branch))
	if !ok {
		return "", false
	}
	if after, ok := strings.CutPrefix(rest, "upcoming "); ok {
		rest = strings.TrimLeft(after, " ")
	}
	for c := range strings.SplitSeq(rest, ".") {
		if c == "" || strings.Trim(c, "0123456789") != "" {
			return "", false
		}
	}
	return rest, true
}

// defineNotAffected defines, as a product_version leaf under its product
// branch, every known_not_affected product_id that the tree does not define.
// Fortinet lists the fixed releases that way (2083 of the 3723
// known_not_affected entries across the corpus as of 2026-09); defining them
// makes the tree say what the list names. A product_id of any other shape, or
// whose branch the tree lacks, hard-errors.
func defineNotAffected(doc *csafTypes.CSAF) error {
	defined := make(map[csafTypes.ProductID]struct{})
	var branches []string
	var walk func(bs []csafTypes.Branch)
	walk = func(bs []csafTypes.Branch) {
		for _, b := range bs {
			if b.Product != nil {
				defined[b.Product.ProductID] = struct{}{}
			}
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
			var (
				branch, version string
				n               int
			)
			for _, b := range branches {
				if ver, ok := notAffectedVersion(pid, b); ok {
					branch, version = b, ver
					n++
				}
			}
			switch n {
			case 0:
				return errors.Errorf("unexpected undefined known_not_affected product %q of %q", pid, v.CVE)
			case 1:
			default:
				return errors.Errorf("undefined known_not_affected product %q of %q matches %d branches", pid, v.CVE, n)
			}
			parent, i, err := findProductBranch(doc.ProductTree.Branches, branch)
			if err != nil {
				return errors.Wrapf(err, "find branch of %q", pid)
			}
			(*parent)[i].Branches = append((*parent)[i].Branches, csafTypes.Branch{
				Category: "product_version",
				Name:     fmt.Sprintf("%s/%s", branch, version),
				Product:  &csafTypes.FullProductName{Name: branch, ProductID: pid},
			})
			defined[pid] = struct{}{}
		}
	}
	return nil
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
				to:   []csafTypes.ProductID{"FortiManager Cloud >=7.4.1|<=7.4.2", "FortiManager >=7.4.0|<=7.4.2"},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager/ 7.6 all versions", "FortiManager-7.4.3", "FortiManager/ 7.2 all versions", "FortiManager/ 7.0 all versions"},
				to:   []csafTypes.ProductID{"FortiManager Cloud-7.4.3", "FortiManager/ 7.6 all versions", "FortiManager-7.4.3", "FortiManager/ 7.2 all versions", "FortiManager/ 7.0 all versions"},
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
				to:   []csafTypes.ProductID{"FortiManager Cloud >=7.4.1|<=7.4.2", "FortiManager >=7.4.0|<=7.4.2"},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager/ 7.6 all versions", "FortiManager-7.4.3", "FortiManager/ 7.2 all versions", "FortiManager/ 7.0 all versions"},
				to:   []csafTypes.ProductID{"FortiManager Cloud-7.4.3", "FortiManager/ 7.6 all versions", "FortiManager-7.4.3", "FortiManager/ 7.2 all versions", "FortiManager/ 7.0 all versions"},
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
				to:   []csafTypes.ProductID{"FortiClientEMS Cloud >=7.2.0|<=7.2.4", "FortiClientEMS Cloud >=7.0.0|<=7.0.12", "FortiClientEMS >=7.2.0|<=7.2.4", "FortiClientEMS >=7.0.0|<=7.0.12"},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiClientEMS/ Cloud 7.4 all versions", "FortiClientEMS-7.2.5", "FortiClientEMS-7.0.13", "FortiClientEMS/ 7.4 all versions", "FortiClientEMS-7.2.5", "FortiClientEMS-7.0.13"},
				to:   []csafTypes.ProductID{"FortiClientEMS Cloud 7.4 all versions", "FortiClientEMS Cloud-7.2.5", "FortiClientEMS Cloud-7.0.13", "FortiClientEMS/ 7.4 all versions", "FortiClientEMS-7.2.5", "FortiClientEMS-7.0.13"},
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
				to:   []csafTypes.ProductID{"FortiManager Cloud 7.0 all versions", "FortiManager Cloud 6.4 all versions", "FortiManager >=7.4.0|<=7.4.2", "FortiManager Cloud >=7.4.1|<=7.4.2", "FortiManager >=7.2.0|<=7.2.5", "FortiManager Cloud >=7.2.1|<=7.2.6", "FortiManager 7.0 all versions", "FortiManager 6.4 all versions", "FortiManager 6.2 all versions", "FortiManager 6.0 all versions"},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager-7.4.3", "FortiManager-7.2.6", "FortiManager-7.2.7"},
				to:   []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager Cloud-7.4.3", "FortiManager-7.2.6", "FortiManager Cloud-7.2.7"},
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
				to:   []csafTypes.ProductID{"FortiManager Cloud >=7.4.1|<=7.4.3", "FortiManager Cloud >=7.2.1|<=7.2.5", "FortiManager Cloud 7.0 all versions", "FortiManager >=7.4.0|<=7.4.3", "FortiManager >=7.2.0|<=7.2.5", "FortiManager 7.0 all versions", "FortiManager 6.4 all versions"},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.4", "FortiManager-7.2.7", "FortiManager/ 7.6 all versions", "FortiManager-7.4.4", "FortiManager-7.2.6"},
				to:   []csafTypes.ProductID{"FortiManager Cloud-7.4.4", "FortiManager Cloud-7.2.7", "FortiManager/ 7.6 all versions", "FortiManager-7.4.4", "FortiManager-7.2.6"},
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
				to:   []csafTypes.ProductID{"FortiManager Cloud >=7.4.1|<=7.4.2", "FortiManager Cloud >=7.2.1|<=7.2.5", "FortiManager Cloud >=7.0.1|<=7.0.12", "FortiManager >=7.4.0|<=7.4.2", "FortiManager >=7.2.0|<=7.2.5", "FortiManager >=7.0.0|<=7.0.12", "FortiManager >=6.4.0|<=6.4.14"},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager-7.2.7", "FortiManager-7.0.13", "FortiManager/ 7.6 all versions", "FortiManager-7.4.3", "FortiManager-7.2.6", "FortiManager-7.0.13", "FortiManager-6.4.15"},
				to:   []csafTypes.ProductID{"FortiManager Cloud-7.4.3", "FortiManager Cloud-7.2.7", "FortiManager Cloud-7.0.13", "FortiManager/ 7.6 all versions", "FortiManager-7.4.3", "FortiManager-7.2.6", "FortiManager-7.0.13", "FortiManager-6.4.15"},
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
				to:   []csafTypes.ProductID{"FortiAnalyzer Cloud >=7.4.1|<=7.4.3", "FortiAnalyzer >=7.6.0|<=7.6.1", "FortiAnalyzer >=7.4.1|<=7.4.3"},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiAnalyzer-7.4.4", "FortiAnalyzer-7.6.2", "FortiAnalyzer-7.4.4", "FortiAnalyzer/ 7.2 all versions", "FortiAnalyzer/ 7.0 all versions"},
				to:   []csafTypes.ProductID{"FortiAnalyzer Cloud-7.4.4", "FortiAnalyzer-7.6.2", "FortiAnalyzer-7.4.4", "FortiAnalyzer/ 7.2 all versions", "FortiAnalyzer/ 7.0 all versions"},
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
				to:   []csafTypes.ProductID{"FortiManager Cloud >=7.4.1|<=7.4.3", "FortiManager >=7.4.1|<=7.4.3"},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.4.4", "FortiManager/ 7.6 all versions", "FortiManager-7.4.4", "FortiManager/ 7.2 all versions", "FortiManager/ 7.0 all versions"},
				to:   []csafTypes.ProductID{"FortiManager Cloud-7.4.4", "FortiManager/ 7.6 all versions", "FortiManager-7.4.4", "FortiManager/ 7.2 all versions", "FortiManager/ 7.0 all versions"},
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
				to:   []csafTypes.ProductID{"FortiManager Cloud >=7.6.0|<=7.6.1", "FortiManager Cloud >=7.4.0|<=7.4.4", "FortiManager Cloud >=7.2.2|<=7.2.7", "FortiManager >=7.6.0|<=7.6.1", "FortiManager >=7.4.0|<=7.4.5", "FortiManager >=7.2.1|<=7.2.8"},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiManager-7.6.2", "FortiManager-7.4.5", "FortiManager-7.2.8", "FortiManager-7.6.2", "FortiManager-7.4.6", "FortiManager-7.2.9", "FortiManager/ 7.0 all versions"},
				to:   []csafTypes.ProductID{"FortiManager Cloud-7.6.2", "FortiManager Cloud-7.4.5", "FortiManager Cloud-7.2.8", "FortiManager-7.6.2", "FortiManager-7.4.6", "FortiManager-7.2.9", "FortiManager/ 7.0 all versions"},
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
				to:   []csafTypes.ProductID{"FortiSandbox Cloud 24 all versions", "FortiSandbox Cloud 23 all versions", "FortiSandbox Cloud >=5.0.2|<=5.0.5"},
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
				to:   []csafTypes.ProductID{},
			},
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiSOAR on-premise-f", "FortiSOAR on-premise-f", "FortiSOAR on-premise-f", "FortiSOAR on-premise-f"},
				to:   []csafTypes.ProductID{},
			},
		},
	},
	// The upcoming fixed release, spelled with a stray "version".
	"FG-IR-25-512": {
		statuses: []statusFix{
			{
				list: knownNotAffected,
				from: []csafTypes.ProductID{"FortiWeb/ 8.0 all versions", "FortiWeb-7.6.5", "FortiWeb-7.4.9", "FortiWeb-upcoming version 7.2.12"},
				to:   []csafTypes.ProductID{"FortiWeb/ 8.0 all versions", "FortiWeb-7.6.5", "FortiWeb-7.4.9", "FortiWeb-upcoming 7.2.12"},
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
				to:   []csafTypes.ProductID{"FortiWebManager all versions", "FortiWeb all versions", "FortiVoice all versions", "FortiTester all versions", "FortiSwitch all versions", "FortiSandbox all versions", "FortiSOAR on-premise all versions", "FortiSIEM all versions", "FortiRecorder all versions", "FortiProxy all versions", "FortiPortal all versions", "FortiOS all versions", "FortiNAC-F/ all versions", "FortiNAC all versions", "FortiManager all versions", "FortiMail all versions", "FortiExtender all versions", "FortiDDoS all versions", "FortiConverter all versions", "FortiCloud all versions", "FortiClientiOS all versions", "FortiClientWindows all versions", "FortiClientMac all versions", "FortiClientLinux all versions", "FortiClientEMS all versions", "FortiClientAndroid all versions", "FortiAuthenticator all versions", "FortiAnalyzer all versions", "FortiAP-W2 all versions", "FortiAP-U all versions", "FortiAP all versions", "FortiADCManager all versions", "FortiADC all versions"},
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
				to:   []csafTypes.ProductID{"FortiSIEM Cloud all versions", "FortiSIEM/ 7.5 all versions", "FortiSIEM-7.4.1", "FortiSIEM-7.3.5", "FortiSIEM-7.2.7", "FortiSIEM-7.1.9"},
			},
		},
	},
}
