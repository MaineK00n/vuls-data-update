package csaf

import (
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	csafTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/csaf"
)

// TestTreeFixRepair exercises the repair mechanism on shapes no published
// advisory has yet, which treeFixes, keyed by advisory, cannot reach.
func TestTreeFixRepair(t *testing.T) {
	type leafOf struct {
		branch string
		pid    csafTypes.ProductID
	}

	tests := []struct {
		name       string
		doc        string
		fix        treeFix
		wantLeaves []leafOf
		wantScores [][]csafTypes.ProductID
		wantErr    bool
	}{
		{
			// A Cloud leaf filed under FortiManager while the tree already has a
			// FortiManager Cloud branch with an object of its own: the leaf joins
			// that branch, yet stays scored by what was written for FortiManager,
			// and so does the fixed Cloud release renamed out of FortiManager's
			// known_not_affected; FortiManager Cloud's own score keeps covering
			// only its own leaves.
			name: "move into a branch the tree already has",
			doc: `{
				"product_tree": {"branches": [{"category": "vendor", "name": "Fortinet PSIRT", "branches": [
					{"category": "product", "name": "FortiManager", "branches": [
						{"category": "product_version_range", "name": "FortiManager/>=7.4.1|<=7.4.2", "product": {"name": "FortiManager", "product_id": "FortiManager >=7.4.1|<=7.4.2"}},
						{"category": "product_version_range", "name": "FortiManager/>=7.4.0|<=7.4.3", "product": {"name": "FortiManager", "product_id": "FortiManager >=7.4.0|<=7.4.3"}}
					]},
					{"category": "product", "name": "FortiManager Cloud", "branches": [
						{"category": "product_version_range", "name": "FortiManager Cloud/>=7.2.1|<=7.2.3", "product": {"name": "FortiManager Cloud", "product_id": "FortiManager Cloud >=7.2.1|<=7.2.3"}}
					]}
				]}]},
				"vulnerabilities": [
					{
						"product_status": {
							"known_affected": ["FortiManager >=7.4.1|<=7.4.2", "FortiManager >=7.4.0|<=7.4.3"],
							"known_not_affected": ["FortiManager-7.4.3", "FortiManager-7.4.4"]
						},
						"scores": [{"products": ["FortiManager"]}]
					},
					{
						"product_status": {"known_affected": ["FortiManager Cloud >=7.2.1|<=7.2.3"]},
						"scores": [{"products": ["FortiManager Cloud"]}]
					}
				]
			}`,
			fix: treeFix{
				branches: []branchFix{{
					name:   "FortiManager",
					leaves: []string{"FortiManager/>=7.4.1|<=7.4.2", "FortiManager/>=7.4.0|<=7.4.3"},
					to:     map[int]leafTarget{0: {product: "FortiManager Cloud", version: ">=7.4.1|<=7.4.2"}},
				}},
				statuses: []statusFix{
					{
						list: knownAffected,
						from: []csafTypes.ProductID{"FortiManager >=7.4.1|<=7.4.2", "FortiManager >=7.4.0|<=7.4.3"},
						to:   map[int]statusTarget{0: {productID: "FortiManager Cloud >=7.4.1|<=7.4.2"}},
					},
					{
						list: knownNotAffected,
						from: []csafTypes.ProductID{"FortiManager-7.4.3", "FortiManager-7.4.4"},
						to:   map[int]statusTarget{0: {productID: "FortiManager Cloud-7.4.3"}},
					},
				},
			},
			wantLeaves: []leafOf{
				{branch: "FortiManager", pid: "FortiManager >=7.4.0|<=7.4.3"},
				{branch: "FortiManager", pid: "FortiManager-7.4.4"},
				{branch: "FortiManager Cloud", pid: "FortiManager Cloud >=7.2.1|<=7.2.3"},
				{branch: "FortiManager Cloud", pid: "FortiManager Cloud >=7.4.1|<=7.4.2"},
				{branch: "FortiManager Cloud", pid: "FortiManager Cloud-7.4.3"},
			},
			wantScores: [][]csafTypes.ProductID{
				{"FortiManager Cloud >=7.4.1|<=7.4.2", "FortiManager >=7.4.0|<=7.4.3", "FortiManager Cloud-7.4.3", "FortiManager-7.4.4"},
				{"FortiManager Cloud >=7.2.1|<=7.2.3"},
			},
		},
		{
			// Two branchFixes of one advisory move leaves into the same new
			// branch: the first creates it, the second adds to it, and each
			// leaf stays scored by what was written for its own branch.
			name: "two branches moving into one new branch",
			doc: `{
				"product_tree": {"branches": [{"category": "vendor", "name": "Fortinet PSIRT", "branches": [
					{"category": "product", "name": "FortiAnalyzer", "branches": [
						{"category": "product_version_range", "name": "FortiAnalyzer/cloud 7.4 all versions", "product": {"name": "FortiAnalyzer", "product_id": "FortiAnalyzer cloud 7.4 all versions"}},
						{"category": "product_version_range", "name": "FortiAnalyzer/7.4 all versions", "product": {"name": "FortiAnalyzer", "product_id": "FortiAnalyzer 7.4 all versions"}}
					]},
					{"category": "product", "name": "FortiAnalyzer-BigData", "branches": [
						{"category": "product_version_range", "name": "FortiAnalyzer-BigData/cloud 7.2 all versions", "product": {"name": "FortiAnalyzer-BigData", "product_id": "FortiAnalyzer-BigData cloud 7.2 all versions"}}
					]}
				]}]},
				"vulnerabilities": [
					{
						"product_status": {"known_affected": ["FortiAnalyzer cloud 7.4 all versions", "FortiAnalyzer 7.4 all versions"]},
						"scores": [{"products": ["FortiAnalyzer"]}]
					},
					{
						"product_status": {"known_affected": ["FortiAnalyzer-BigData cloud 7.2 all versions"]},
						"scores": [{"products": ["FortiAnalyzer-BigData"]}]
					}
				]
			}`,
			fix: treeFix{
				branches: []branchFix{
					{
						name:   "FortiAnalyzer",
						leaves: []string{"FortiAnalyzer/cloud 7.4 all versions", "FortiAnalyzer/7.4 all versions"},
						to:     map[int]leafTarget{0: {product: "FortiAnalyzer Cloud", version: "7.4 all versions"}},
					},
					{
						name:   "FortiAnalyzer-BigData",
						leaves: []string{"FortiAnalyzer-BigData/cloud 7.2 all versions"},
						to:     map[int]leafTarget{0: {product: "FortiAnalyzer Cloud", version: "7.2 all versions"}},
					},
				},
				statuses: []statusFix{
					{
						list: knownAffected,
						from: []csafTypes.ProductID{"FortiAnalyzer cloud 7.4 all versions", "FortiAnalyzer 7.4 all versions"},
						to:   map[int]statusTarget{0: {productID: "FortiAnalyzer Cloud 7.4 all versions"}},
					},
					{
						list: knownAffected,
						from: []csafTypes.ProductID{"FortiAnalyzer-BigData cloud 7.2 all versions"},
						to:   map[int]statusTarget{0: {productID: "FortiAnalyzer Cloud 7.2 all versions"}},
					},
				},
			},
			wantLeaves: []leafOf{
				{branch: "FortiAnalyzer", pid: "FortiAnalyzer 7.4 all versions"},
				{branch: "FortiAnalyzer Cloud", pid: "FortiAnalyzer Cloud 7.4 all versions"},
				{branch: "FortiAnalyzer Cloud", pid: "FortiAnalyzer Cloud 7.2 all versions"},
			},
			wantScores: [][]csafTypes.ProductID{
				{"FortiAnalyzer Cloud 7.4 all versions", "FortiAnalyzer 7.4 all versions"},
				{"FortiAnalyzer Cloud 7.2 all versions"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc csafTypes.CSAF
			if err := json.UnmarshalRead(strings.NewReader(tt.doc), &doc); err != nil {
				t.Fatal(err)
			}
			err := tt.fix.repair(&doc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("repair() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			var gotLeaves []leafOf
			var walk func(bs []csafTypes.Branch, branch string)
			walk = func(bs []csafTypes.Branch, branch string) {
				for _, b := range bs {
					if b.Category == "product" {
						branch = b.Name
					}
					if b.Product != nil {
						gotLeaves = append(gotLeaves, leafOf{branch: branch, pid: b.Product.ProductID})
					}
					walk(b.Branches, branch)
				}
			}
			walk(doc.ProductTree.Branches, "")
			if diff := cmp.Diff(tt.wantLeaves, gotLeaves, cmp.AllowUnexported(leafOf{})); diff != "" {
				t.Errorf("leaves (-expected +got):\n%s", diff)
			}

			var gotScores [][]csafTypes.ProductID
			for _, v := range doc.Vulnerabilities {
				for _, sc := range v.Scores {
					gotScores = append(gotScores, sc.Products)
				}
			}
			if diff := cmp.Diff(tt.wantScores, gotScores); diff != "" {
				t.Errorf("scores (-expected +got):\n%s", diff)
			}
		})
	}
}
