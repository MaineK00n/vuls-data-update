package bulletin_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/bulletin"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
	fetch "github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/bulletin"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		hasError bool
	}{
		{
			name: "happy",
			args: "./testdata/fixtures",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := bulletin.Extract(tt.args, bulletin.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				return
			default:
				ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
				if err != nil {
					t.Error("unexpected error:", err)
				}
				gp, err := filepath.Abs(dir)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				utiltest.Diff(t, ep, gp)
			}
		})
	}
}

func Test_productName(t *testing.T) {
	type args struct {
		product   string
		component string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty component",
			args: args{product: "Microsoft Office 2010 Service Pack 1 (32-bit editions)", component: ""},
			want: "Microsoft Office 2010 Service Pack 1 (32-bit editions)",
		},
		{
			name: "component equals product",
			args: args{product: "Windows 7 for 32-bit Systems Service Pack 1", component: "Windows 7 for 32-bit Systems Service Pack 1"},
			want: "Windows 7 for 32-bit Systems Service Pack 1",
		},
		{
			name: "product is Windows OS, component is app",
			args: args{product: "Windows 7 for 32-bit Systems Service Pack 1", component: "Internet Explorer 11"},
			want: "Internet Explorer 11 on Windows 7 for 32-bit Systems Service Pack 1",
		},
		{
			name: "product is Microsoft Windows OS, component is app",
			args: args{product: "Microsoft Windows XP Service Pack 3", component: "Windows Internet Explorer 7"},
			want: "Windows Internet Explorer 7 on Microsoft Windows XP Service Pack 3",
		},
		{
			name: "product is app, component is Windows OS",
			args: args{product: "Internet Explorer 9", component: "Windows Vista Service Pack 2"},
			want: "Internet Explorer 9 on Windows Vista Service Pack 2",
		},
		{
			name: "product is Windows Server",
			args: args{product: "Windows Server 2012", component: "Internet Explorer 10"},
			want: "Internet Explorer 10 on Windows Server 2012",
		},
		{
			name: "product is Windows RT",
			args: args{product: "Windows RT 8.1", component: "Windows Internet Explorer 11"},
			want: "Windows Internet Explorer 11 on Windows RT 8.1",
		},
		{
			name: "product is Windows 10",
			args: args{product: "Windows 10 Version 1511 for x64-based Systems", component: "Adobe Flash Player"},
			want: "Adobe Flash Player on Windows 10 Version 1511 for x64-based Systems",
		},
		{
			name: "product is Microsoft Windows 2000",
			args: args{product: "Microsoft Windows 2000 Service Pack 4", component: "Microsoft XML Core Services 3.0"},
			want: "Microsoft XML Core Services 3.0 on Microsoft Windows 2000 Service Pack 4",
		},
		{
			name: "product is Windows NT",
			args: args{product: "Microsoft Windows NT Server 4.0 Service Pack 6a", component: "Microsoft Internet Information Server 4.0"},
			want: "Microsoft Internet Information Server 4.0 on Microsoft Windows NT Server 4.0 Service Pack 6a",
		},
		{
			name: "product is Windows Embedded",
			args: args{product: "Windows Embedded CE 6.0", component: "DirectShow"},
			want: "DirectShow on Windows Embedded CE 6.0",
		},
		{
			name: "component is SharePoint Server",
			args: args{product: "Word Automation Services", component: "Microsoft SharePoint Server 2010 Service Pack 1"},
			want: "Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 1",
		},
		{
			name: "product is SharePoint Server",
			args: args{product: "Microsoft SharePoint Server 2010 Service Pack 2", component: "Word Automation Services"},
			want: "Word Automation Services on Microsoft SharePoint Server 2010 Service Pack 2",
		},
		{
			name: "Office suite to Office app",
			args: args{product: "Microsoft Office 2010 Service Pack 1 (32-bit editions)", component: "Microsoft Word 2010 Service Pack 1 (32-bit editions)"},
			want: "Microsoft Word 2010 Service Pack 1 (32-bit editions)",
		},
		{
			name: "Office suite to XML Core Services",
			args: args{product: "Microsoft Office 2007 Service Pack 3", component: "Microsoft XML Core Services 5.0"},
			want: "Microsoft XML Core Services 5.0",
		},
		{
			name: "non-platform product to non-platform component",
			args: args{product: "Microsoft Office for Mac 2011", component: "Microsoft Word for Mac 2011"},
			want: "Microsoft Word for Mac 2011",
		},
		{
			name: "Windows-prefixed app is not a platform",
			args: args{product: "Microsoft Office 2010 Service Pack 2 (32-bit editions)", component: "Windows Internet Explorer 8"},
			want: "Windows Internet Explorer 8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bulletin.ProductName(tt.args.product, tt.args.component); got != tt.want {
				t.Errorf("productName() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIECumChainEdges verifies known IE Cumulative chain edges in the
// per-bulletin amendments. Edges are aggregated globally at extract time
// (across all bulletins' IECumChain maps), bridging the Nov 2016 MS16-142
// gap that the chain-merge loop specifically targets. Verification scans
// every bulletin's IECumChain for the (oldKB → newKB) edge — accurate
// owner attribution is best-effort and not required for the chain walk.
func TestIECumChainEdges(t *testing.T) {
	tests := []struct {
		name    string
		oldKBID string
		newKBID string
	}{
		{
			name:    "MS16-118 IE 11 Win 8.1 → MS16-142 (Microsoft did not publish this edge)",
			oldKBID: "3192392",
			newKBID: "3197873",
		},
		{
			name:    "MS16-118 IE 11 Win 7 → MS16-142 (Microsoft did not publish this edge)",
			oldKBID: "3192391",
			newKBID: "3197867",
		},
		{
			name:    "KB2957689 (IE 11 Cum May 2014, blocks 120 CVEs) → KB2962872",
			oldKBID: "2957689",
			newKBID: "2962872",
		},
		{
			name:    "MS16-142 IE 11 Win 7 → MS16-144 (no Microsoft edge)",
			oldKBID: "3197867",
			newKBID: "3205394",
		},
		{
			name:    "MS16-142 IE 11 Win 8.1 → MS16-144 (no Microsoft edge)",
			oldKBID: "3197873",
			newKBID: "3205400",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, ad := range bulletin.BulletinArchiveAmendments {
				if news, ok := ad.IECumChain[tt.oldKBID]; ok {
					if slices.Contains(news, tt.newKBID) {
						found = true
						break
					}
				}
			}
			if !found {
				t.Errorf("no bulletinArchiveAmendments[*].IECumChain contains edge %q → %q", tt.oldKBID, tt.newKBID)
			}
		})
	}
}

// TestBulletinArchiveSupersedes verifies known supersedes Add edges in the
// per-bulletin amendments. Each bulletin's Supersedes[oldKB].Add lists the
// new KBs that supersede oldKB (recovered from the bulletin's archive
// markdown where BulletinSearch.xlsx omits the edge).
func TestBulletinArchiveSupersedes(t *testing.T) {
	tests := []struct {
		name       string
		bulletinID string
		oldKBID    string
		newKBID    string
	}{
		{
			name:       "MS13-054 Lync 2010 Attendee user install: 2827751 → 2843162 (Excel attributed Lync admin KB instead)",
			bulletinID: "MS13-054",
			oldKBID:    "2827751",
			newKBID:    "2843162",
		},
		{
			name:       "MS13-054 Lync 2010 Attendee admin install: 2827752 → 2843163",
			bulletinID: "MS13-054",
			oldKBID:    "2827752",
			newKBID:    "2843163",
		},
		{
			name:       "MS14-029 IE Win Server: 2936068 → 2953522 (Excel missed)",
			bulletinID: "MS14-029",
			oldKBID:    "2936068",
			newKBID:    "2953522",
		},
		{
			name:       "MS14-037 IE 8 (Vista SP2) / IE 11 (Win7 SP1) IE Cum chain: 2957689 → 2962872",
			bulletinID: "MS14-037",
			oldKBID:    "2957689",
			newKBID:    "2962872",
		},
		{
			name:       "MS16-144 IE 9 Cumulative (Vista SP2): 3197655 → 3203621",
			bulletinID: "MS16-144",
			oldKBID:    "3197655",
			newKBID:    "3203621",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad, ok := bulletin.BulletinArchiveAmendments[tt.bulletinID]
			if !ok {
				t.Fatalf("bulletinArchiveAmendments has no entry for %s", tt.bulletinID)
			}
			adj, ok := ad.Supersedes[tt.oldKBID]
			if !ok {
				t.Fatalf("bulletinArchiveAmendments[%q].Supersedes has no entry for KB%s", tt.bulletinID, tt.oldKBID)
			}
			if !slices.Contains(adj.Add, tt.newKBID) {
				t.Errorf("bulletinArchiveAmendments[%q].Supersedes[%q].Add = %v, want to contain %q", tt.bulletinID, tt.oldKBID, adj.Add, tt.newKBID)
			}
		})
	}
}

// TestBulletinArchiveSupersedesOverride verifies known supersedes Override
// edges in the per-bulletin amendments. These are KB pairs where the frozen
// BulletinSearch.xlsx Supersedes column attributes the supersedes to the
// wrong component_kb (Excel mis-attribution); the Microsoft Learn archive
// records a different ancestry. Each test asserts that the override would
// remove the wrong edge.
//
// End-to-end coverage of the deletion loop in extract() is provided by the
// MS13-054 fixture (testdata/fixtures/13/MS13-054.json): its two rows are
// the Lync 2010 Attendee user/admin install components (KB2843162/2843163)
// whose Excel-cited supersedes (MS13-041[2827750]) is dropped by this
// override and whose correct supersedes (KB2827751/2827752) is then added
// by the same bulletin's Supersedes Add edges.
func TestBulletinArchiveSupersedesOverride(t *testing.T) {
	tests := []struct {
		name       string
		bulletinID string
		newKBID    string
		oldKBID    string
	}{
		{
			name:       "MS13-054 Lync 2010 Attendee user install (2843162): drop wrong edge from KB2827750 (which actually fixes the 64-bit pkg)",
			bulletinID: "MS13-054",
			newKBID:    "2843162",
			oldKBID:    "2827750",
		},
		{
			name:       "MS13-054 Lync 2010 Attendee admin install (2843163): drop wrong edge from KB2827750",
			bulletinID: "MS13-054",
			newKBID:    "2843163",
			oldKBID:    "2827750",
		},
		{
			name:       "MS15-062 ADFS (3062577): drop self-supersedes (Excel claims KB3062577 supersedes itself)",
			bulletinID: "MS15-062",
			newKBID:    "3062577",
			oldKBID:    "3062577",
		},
		{
			name:       "MS16-054 Word 2016 (3115094): drop wrong edge from KB3142577 (Excel cited a later unrelated KB)",
			bulletinID: "MS16-054",
			newKBID:    "3115094",
			oldKBID:    "3142577",
		},
		{
			name:       "MS16-054 Word 2016 (3115094): drop wrong edge from KB3154208",
			bulletinID: "MS16-054",
			newKBID:    "3115094",
			oldKBID:    "3154208",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad, ok := bulletin.BulletinArchiveAmendments[tt.bulletinID]
			if !ok {
				t.Fatalf("bulletinArchiveAmendments has no entry for %s", tt.bulletinID)
			}
			adj, ok := ad.Supersedes[tt.oldKBID]
			if !ok {
				t.Fatalf("bulletinArchiveAmendments[%q].Supersedes has no entry for KB%s", tt.bulletinID, tt.oldKBID)
			}
			if !slices.Contains(adj.Override, tt.newKBID) {
				t.Errorf("bulletinArchiveAmendments[%q].Supersedes[%q].Override = %v, want to contain %q", tt.bulletinID, tt.oldKBID, adj.Override, tt.newKBID)
			}
		})
	}
}

func Test_normalizeArchiveComponentKey(t *testing.T) {
	type args struct {
		bulletinID string
		product    string
		component  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// IE/Edge global vocabulary — the default branch of normalizeArchiveComponentKey,
		// reached only when bulletinID is not one of the MS06-* product-keyed cases.
		// Cases below use representative IE Cumulative bulletin IDs (MS14-010, MS16-037).
		{
			name: "IE 11 on legacy Windows 7",
			args: args{bulletinID: "MS14-010", product: "Windows 7 for x64-based Systems Service Pack 1", component: "Windows Internet Explorer 11"},
			want: "Internet Explorer 11",
		},
		{
			name: "IE 11 on Windows 10",
			args: args{bulletinID: "MS16-037", product: "Windows 10 for x64-based Systems", component: "Internet Explorer 11"},
			want: "Internet Explorer 11 on Windows 10",
		},
		{
			name: "IE 9 (Internet Explorer prefix)",
			args: args{bulletinID: "MS14-010", product: "Windows Server 2008 for x64-based Systems Service Pack 2", component: "Internet Explorer 9"},
			want: "Internet Explorer 9",
		},
		{
			name: "IE 6.0 (Microsoft Internet Explorer prefix)",
			args: args{bulletinID: "MS14-010", product: "Microsoft Windows Server 2003 Service Pack 2", component: "Microsoft Internet Explorer 6.0"},
			want: "Internet Explorer 6",
		},
		{
			name: "Microsoft Edge",
			args: args{bulletinID: "MS16-037", product: "Windows 10 for x64-based Systems", component: "Microsoft Edge"},
			want: "Microsoft Edge",
		},
		// Per-bulletin non-IE product vocabularies.
		{
			name: "MS06-012 PowerPoint 2000 SP3 → bundled markdown column",
			args: args{bulletinID: "MS06-012", product: "Microsoft Office 2000 Service Pack 3", component: "Microsoft PowerPoint 2000 Service Pack 3"},
			want: "Microsoft PowerPoint 2000",
		},
		{
			// Dispatch is present for forward compatibility but the current
			// BulletinSearch.xlsx never carries these rows under MS06-020.
			name: "MS06-020 Win 2000 SP4 (hypothetical Excel row) → markdown column",
			args: args{bulletinID: "MS06-020", product: "Microsoft Windows 2000 Service Pack 4", component: ""},
			want: "Windows 2000",
		},
		{
			name: "MS06-020 Server 2003 SP1 (hypothetical Excel row) → markdown column",
			args: args{bulletinID: "MS06-020", product: "Microsoft Windows Server 2003 Service Pack 1", component: ""},
			want: "Windows Server 2003 Service Pack 1",
		},
		{
			name: "MS06-039 Project 2000 (component is null, match affected_product)",
			args: args{bulletinID: "MS06-039", product: "Microsoft Project 2000", component: ""},
			want: "Microsoft Project 2000",
		},
		// MS06-060 is intentionally absent from normalizeArchiveComponentKey
		// — its NA cells are captured by KB-scoped Drop entries in
		// bulletinArchiveAmendments (KB923088/923089/923090/924998/924999),
		// not via component-keyed narrowing. Verify the default branch returns
		// "" so the row passes through to the KB-keyed filter.
		{
			name: "MS06-060 Word 2003 SP1 row passes through normalizer (KB-keyed instead)",
			args: args{bulletinID: "MS06-060", product: "Microsoft Office 2003 Service Pack 1", component: "Microsoft Word 2003 Service Pack 1"},
			want: "",
		},
		{
			name: "MS06-060 Works Suite row with null component passes through (KB-keyed instead)",
			args: args{bulletinID: "MS06-060", product: "Microsoft Works Suite 2004", component: ""},
			want: "",
		},
		{
			name: "MS06-078 WMP 6.4 → \"all operating systems\" column",
			args: args{bulletinID: "MS06-078", product: "Microsoft Windows XP Service Pack 2", component: "Microsoft Windows Media Player 6.4"},
			want: "Windows Media Player 6.4 (All operating systems)",
		},
		// Bulletin-specific vocabulary does NOT apply outside its bulletin.
		{
			name: "MS06-012 PowerPoint key not recognized in a different bulletin",
			args: args{bulletinID: "MS07-001", product: "Microsoft Office 2000 Service Pack 3", component: "Microsoft PowerPoint 2000 Service Pack 3"},
			want: "",
		},
		// Negative cases.
		{
			name: "non-IE component in an IE-vocabulary bulletin returns empty",
			args: args{bulletinID: "MS14-010", product: "Microsoft Office 2010 Service Pack 1 (32-bit editions)", component: "Microsoft Word 2010 Service Pack 1 (32-bit editions)"},
			want: "",
		},
		{
			name: "empty component in IE Cumulative bulletin (default IE/Edge branch) returns empty",
			args: args{bulletinID: "MS14-010", product: "Windows 7 for x64-based Systems Service Pack 1", component: ""},
			want: "",
		},
		// MS17-006 (and likely the broader MS17 era) swaps the IE identity into
		// affected_product and the OS into affected_component, so it has its
		// own case in the dispatch (the default branch handles the MS14-MS16
		// layout where IE is in affected_component). Verify that the
		// MS17-006 case correctly maps the swapped columns to the same IE
		// key vocabulary.
		{
			name: "MS17-006 swap: IE 9 in affected_product, OS in affected_component",
			args: args{bulletinID: "MS17-006", product: "Internet Explorer 9", component: "Windows Vista Service Pack 2"},
			want: "Internet Explorer 9",
		},
		{
			name: "MS17-006 swap: IE 11 on legacy Windows 7 via swapped columns",
			args: args{bulletinID: "MS17-006", product: "Internet Explorer 11", component: "Windows 7 for x64-based Systems Service Pack 1"},
			want: "Internet Explorer 11",
		},
		{
			name: "MS17-006 swap: IE 11 on Windows 10 — Windows 10 marker is in component",
			args: args{bulletinID: "MS17-006", product: "Internet Explorer 11", component: "Windows 10 for x64-based Systems"},
			want: "Internet Explorer 11 on Windows 10",
		},
		// Mixed-applicability bulletins return the whitespace-normalized
		// affected_product as the inner key, so the filter looks the xlsx
		// label up against the Component-scoped Drop entries in
		// bulletinArchiveAmendments after the same whitespace normalization
		// (strings.Fields/Join collapse). Verify that the dispatch returns the
		// product string (not empty) for a few representative bulletins across
		// MS12-, MS15-, MS16-, and MS17-.
		{
			name: "MS16-106 mixed-applicability: returns affected_product (Win Server 2008 SP2)",
			args: args{bulletinID: "MS16-106", product: "Windows Server 2008 for 32-bit Systems Service Pack 2", component: ""},
			want: "Windows Server 2008 for 32-bit Systems Service Pack 2",
		},
		{
			name: "MS16-106 mixed-applicability: collapses internal whitespace runs",
			args: args{bulletinID: "MS16-106", product: "Windows Server  2008  for 32-bit Systems Service Pack 2", component: ""},
			want: "Windows Server 2008 for 32-bit Systems Service Pack 2",
		},
		{
			name: "MS17-018 mixed-applicability: returns Server 2016 Server Core label (must match the spaced variant in the map)",
			args: args{bulletinID: "MS17-018", product: "Windows Server 2016 for x64-based Systems (Server Core installation)", component: ""},
			want: "Windows Server 2016 for x64-based Systems (Server Core installation)",
		},
		{
			name: "MS15-128 mixed-applicability: returns Windows 7 SP1",
			args: args{bulletinID: "MS15-128", product: "Windows 7 for 32-bit Systems Service Pack 1", component: ""},
			want: "Windows 7 for 32-bit Systems Service Pack 1",
		},
		{
			name: "MS12-054 mixed-applicability: returns Windows 7",
			args: args{bulletinID: "MS12-054", product: "Windows 7 for 32-bit Systems", component: ""},
			want: "Windows 7 for 32-bit Systems",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bulletin.NormalizeArchiveComponentKey(tt.args.bulletinID, tt.args.product, tt.args.component); got != tt.want {
				t.Errorf("normalizeArchiveComponentKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBulletinArchiveNotApplicable verifies known KB-scoped and
// Component-scoped Drop entries in bulletinArchiveAmendments, used to correct
// Excel's lossy per-CVE attribution. The amendments are regenerated from the
// frozen Bulletin archive markdown corpus (1554 bulletins, retired April
// 2017), so any regression in their structure (e.g., a generator change
// dropping a recognized header label, or stripping a CVE attribution) should
// fail this test. End-to-end coverage that the filter actually drops the
// over-attributed CVEs is provided by the MS14-010 golden test.
func TestBulletinArchiveNotApplicable(t *testing.T) {
	t.Run("KB-keyed", func(t *testing.T) {
		tests := []struct {
			name        string
			bulletinID  string
			componentKB string
			cve         string
		}{
			{
				name:        "MS16-007 KB3108664 NA for CVE-2016-0019 (per-CVE columns under \"Operating System\" header)",
				bulletinID:  "MS16-007",
				componentKB: "3108664",
				cve:         "CVE-2016-0019",
			},
			{
				name:        "MS13-040 KB2804576 (.NET 4) NA for CVE-2013-1337 (under \"Affected Software\" header)",
				bulletinID:  "MS13-040",
				componentKB: "2804576",
				cve:         "CVE-2013-1337",
			},
			// MS06-060 NA via KB-keyed. KB923089 is shared by Word 2002 SP3 +
			// Works Suite 2004/2005/2006 — per the Microsoft footnote "Works
			// Suite severity = Word 2002 severity", so the Word 2002 column's
			// NA cell drops CVE-2006-4693 from all four rows simultaneously.
			{
				name:        "MS06-060 KB923089 (Word 2002 SP3 + Works Suite 2004/2005/2006) NA for CVE-2006-4693",
				bulletinID:  "MS06-060",
				componentKB: "923089",
				cve:         "CVE-2006-4693",
			},
			{
				name:        "MS06-060 KB924998 (Office v. X for Mac) NA for CVE-2006-3651 (Word for Mac column)",
				bulletinID:  "MS06-060",
				componentKB: "924998",
				cve:         "CVE-2006-3651",
			},
			{
				name:        "MS06-060 KB924999 (Word 2004 for Mac) NA for CVE-2006-4534 (Word for Mac column)",
				bulletinID:  "MS06-060",
				componentKB: "924999",
				cve:         "CVE-2006-4534",
			},
			{
				name:        "MS13-004 KB2742613 (.NET 4.5) NA for CVE-2013-0001 (explicit \"Not applicable\" cell; KB appears as \"(KB2742613)\" — covered by extended regex)",
				bulletinID:  "MS13-004",
				componentKB: "2742613",
				cve:         "CVE-2013-0001",
			},
			{
				name:        "MS16-106 KB3185911 NA for CVE-2016-3356 (markdown uses \"Not applicable\" — uniformly NA across all 19 xlsx rows of this shared KB)",
				bulletinID:  "MS16-106",
				componentKB: "3185911",
				cve:         "CVE-2016-3356",
			},
			{
				name:        "MS16-106 KB3189866 (Windows 10 Version 1607) NA for CVE-2016-3349 (markdown uses \"Not affected\" — exercises the legacy-marker predicate; uniformly NA across both xlsx rows of this shared KB)",
				bulletinID:  "MS16-106",
				componentKB: "3189866",
				cve:         "CVE-2016-3349",
			},
			{
				name:        "MS16-107 KB3185852 (Microsoft Visio 2016) NA for CVE-2016-3357 (multi-table-KB bulletin where per-(KB, CVE) is single-table and uniformly NA — newly reachable after the per-(KB, CVE) classification fix)",
				bulletinID:  "MS16-107",
				componentKB: "3185852",
				cve:         "CVE-2016-3357",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ad, ok := bulletin.BulletinArchiveAmendments[tt.bulletinID]
				if !ok {
					t.Fatalf("bulletinArchiveAmendments has no entry for %s", tt.bulletinID)
				}
				found := false
				for _, adj := range ad.CVEAdjustments {
					if adj.KB != tt.componentKB {
						continue
					}
					if slices.Contains(adj.Drop, tt.cve) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("bulletinArchiveAmendments[%q] CVEAdjustments has no KB=%q Drop %q", tt.bulletinID, tt.componentKB, tt.cve)
				}
			})
		}
	})
	t.Run("Per-bulletin inner-key", func(t *testing.T) {
		// The Component-scoped Drop entries' inner key has three flavors:
		// IE/Edge vocabulary keys, MS06-* column header strings, and
		// whitespace-normalized affected_product strings for the
		// mixed-applicability bulletins. This subtest covers all three.
		tests := []struct {
			name       string
			bulletinID string
			innerKey   string
			cve        string
		}{
			// IE/Edge vocabulary flavor.
			{
				name:       "MS16-037 IE 11 NA for CVE-2016-0159 (IE Cumulative, CVE-rows × IE-version cols)",
				bulletinID: "MS16-037",
				innerKey:   "Internet Explorer 11",
				cve:        "CVE-2016-0159",
			},
			{
				name:       "MS14-010 IE 11 NA for CVE-2014-0269 (IE Cumulative, verified by golden diff)",
				bulletinID: "MS14-010",
				innerKey:   "Internet Explorer 11",
				cve:        "CVE-2014-0269",
			},
			// MS06-* column-header vocabulary flavor.
			{
				name:       "MS06-012 PowerPoint 2000 NA for CVE-2005-4131 (Office cross-product table)",
				bulletinID: "MS06-012",
				innerKey:   "Microsoft PowerPoint 2000",
				cve:        "CVE-2005-4131",
			},
			{
				name:       "MS06-020 Win 2000 NA for CVE-2006-0024 (no current Excel row triggers; kept for completeness)",
				bulletinID: "MS06-020",
				innerKey:   "Windows 2000",
				cve:        "CVE-2006-0024",
			},
			{
				name:       "MS06-039 Project 2000 NA for CVE-2006-0033",
				bulletinID: "MS06-039",
				innerKey:   "Microsoft Project 2000",
				cve:        "CVE-2006-0033",
			},
			// MS06-060 NA cells are encoded as KB-scoped Drop entries
			// (KB-keyed), not here. See the corresponding KB-keyed test cases.
			{
				name:       "MS06-078 WMP 6.4 NA for CVE-2006-6134",
				bulletinID: "MS06-078",
				innerKey:   "Windows Media Player 6.4 (All operating systems)",
				cve:        "CVE-2006-6134",
			},
			// Mixed-applicability product-keyed flavor: the KB is shared
			// across multiple xlsx rows whose per-CVE matrix cells differ
			// in NA status, so the filter dispatches on the whitespace-
			// normalized affected_product (NormalizeArchiveComponentKey
			// collapses whitespace via strings.Fields/Join before returning)
			// and the inner key here is that normalized affected_product.
			{
				name:       "MS16-106 Windows Server 2008 NA for CVE-2016-3349 (KB3185911 shared with Win 8.1+ where the CVE is applicable)",
				bulletinID: "MS16-106",
				innerKey:   "Windows Server 2008 for 32-bit Systems Service Pack 2",
				cve:        "CVE-2016-3349",
			},
			// Bulletins where the same KB appears in multiple per-CVE matrix
			// tables of the bulletin, but the per-(KB, CVE) cells are
			// single-table — so product-keyed dispatch is still safe for those
			// specific pairs even though the KB itself spans tables.
			{
				name:       "MS15-097 Windows Vista SP2 NA for CVE-2015-2527 (KB3087039 spans two per-CVE tables; this (KB, CVE) appears only in T1, mixed across OS rows there)",
				bulletinID: "MS15-097",
				innerKey:   "Windows Vista Service Pack 2",
				cve:        "CVE-2015-2527",
			},
			{
				name:       "MS15-128 Windows 7 SP1 NA for CVE-2015-6106 (KB3116869 spans OS+component tables; the cross-table-mixed (KB, CVE-2015-6108) pair is correctly excluded — see below)",
				bulletinID: "MS15-128",
				innerKey:   "Windows 7 for 32-bit Systems Service Pack 1",
				cve:        "CVE-2015-6106",
			},
			{
				name:       "MS16-107 Microsoft Office 2013 SP1 NA for CVE-2016-3357 (multi-table-KB bulletin newly reachable via dispatch)",
				bulletinID: "MS16-107",
				innerKey:   "Microsoft Office 2013 Service Pack 1 (32-bit editions)",
				cve:        "CVE-2016-3357",
			},
			{
				name:       "MS16-133 Microsoft Word for Mac 2011 NA for CVE-2016-7228 (multi-table-KB bulletin newly reachable via dispatch)",
				bulletinID: "MS16-133",
				innerKey:   "Microsoft Word for Mac 2011",
				cve:        "CVE-2016-7228",
			},
			{
				name:       "MS17-018 Windows Server 2016 (Server Core) NA for CVE-2017-0024 (multi-table-KB bulletin newly reachable via dispatch)",
				bulletinID: "MS17-018",
				innerKey:   "Windows Server 2016 for x64-based Systems (Server Core installation)",
				cve:        "CVE-2017-0024",
			},
			// MS15-128 / KB3116869 / CVE-2015-6108 is "Not applicable" in the
			// OS-level table but "Critical Remote Code Execution" in the same
			// bulletin's component-level table, with the same xlsx
			// affected_product label for both. A (bulletin, component) NA
			// Drop entry cannot disambiguate at this grain. This case is now
			// handled by the bulletin's RowSplits in bulletinArchiveAmendments,
			// which splits the OS-only xlsx row into an OS-only row + a
			// synthesized "OS + .NET Framework 3.5" row carrying CVE-2015-6108.
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ad, ok := bulletin.BulletinArchiveAmendments[tt.bulletinID]
				if !ok {
					t.Fatalf("bulletinArchiveAmendments has no entry for %s", tt.bulletinID)
				}
				found := false
				for _, adj := range ad.CVEAdjustments {
					if adj.Component != tt.innerKey {
						continue
					}
					if slices.Contains(adj.Drop, tt.cve) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("bulletinArchiveAmendments[%q] CVEAdjustments has no Drop %q for component %q", tt.bulletinID, tt.cve, tt.innerKey)
				}
			})
		}
	})
}

// TestBulletinArchiveCVECorrections verifies known CVE token remap/drop
// entries in bulletinArchiveAmendments. Each per-bulletin CVEAdjustments
// list may carry a Remap map keyed by the xlsx CVE token; a non-empty
// value remaps to a canonical CVE, an empty value drops the token.
// Both branches are exercised below.
func TestBulletinArchiveCVECorrections(t *testing.T) {
	tests := []struct {
		name       string
		bulletinID string
		token      string
		wantFix    string
		wantOK     bool
	}{
		{
			name:       "MS06-012 remap: year-typo CVE-2006-4131 → CVE-2005-4131",
			bulletinID: "MS06-012",
			token:      "CVE-2006-4131",
			wantFix:    "CVE-2005-4131",
			wantOK:     true,
		},
		{
			name:       "MS11-056 remap: off-by-one CVE-2011-1285 → CVE-2011-1284",
			bulletinID: "MS11-056",
			token:      "CVE-2011-1285",
			wantFix:    "CVE-2011-1284",
			wantOK:     true,
		},
		{
			name:       "MS16-084 drop: CVE-2016-3276 retracted by Microsoft V1.1 revision",
			bulletinID: "MS16-084",
			token:      "CVE-2016-3276",
			wantFix:    "",
			wantOK:     true,
		},
		{
			name:       "MS06-021 drop: CVE-2006-2283 has no candidate in markdown",
			bulletinID: "MS06-021",
			token:      "CVE-2006-2283",
			wantFix:    "",
			wantOK:     true,
		},
		{
			name:       "no entry for unknown bulletin",
			bulletinID: "MS00-000",
			token:      "CVE-1999-9999",
			wantOK:     false,
		},
		{
			name:       "known bulletin but unknown token returns ok=false",
			bulletinID: "MS06-012",
			token:      "CVE-2099-0001",
			wantOK:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad, ok := bulletin.BulletinArchiveAmendments[tt.bulletinID]
			if !ok {
				if tt.wantOK {
					t.Fatalf("bulletinArchiveAmendments has no entry for %s", tt.bulletinID)
				}
				return
			}
			var fix string
			found := false
			for _, adj := range ad.CVEAdjustments {
				if v, ok := adj.Remap[tt.token]; ok {
					fix = v
					found = true
					break
				}
			}
			if found != tt.wantOK {
				t.Errorf("bulletinArchiveAmendments[%q] Remap[%q] ok = %v, want %v", tt.bulletinID, tt.token, found, tt.wantOK)
			}
			if fix != tt.wantFix {
				t.Errorf("bulletinArchiveAmendments[%q] Remap[%q] = %q, want %q", tt.bulletinID, tt.token, fix, tt.wantFix)
			}
		})
	}
}

func TestApplyComponentReattributions(t *testing.T) {
	tests := []struct {
		name string
		in   []fetch.Bulletin
		want []fetch.Bulletin
	}{
		{
			name: "row without a split entry is passed through unchanged",
			in: []fetch.Bulletin{
				{BulletinID: "MS15-097", AffectedProduct: "Windows 7 for 32-bit Systems Service Pack 1", ComponentKB: "3087039", CVEs: "CVE-2015-2506,CVE-2015-2507"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS15-097", AffectedProduct: "Windows 7 for 32-bit Systems Service Pack 1", ComponentKB: "3087039", CVEs: "CVE-2015-2506,CVE-2015-2507"},
			},
		},
		{
			name: "MS15-128 KB3116869 Win 10 32-bit row is split into OS-only + .NET 3.5 rows",
			in: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", ComponentKB: "3116869", CVEs: "CVE-2015-6106,CVE-2015-6107,CVE-2015-6108"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", ComponentKB: "3116869", CVEs: "CVE-2015-6106,CVE-2015-6107"},
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", AffectedComponent: "Microsoft .NET Framework 3.5", ComponentKB: "3116869", CVEs: "CVE-2015-6108"},
			},
		},
		{
			name: "lowercase bulletin_id matches the dispatch case-insensitively",
			in: []fetch.Bulletin{
				{BulletinID: "ms15-128", AffectedProduct: "Windows 10 for x64-based Systems", ComponentKB: "3116869", CVEs: "CVE-2015-6106,CVE-2015-6108"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "ms15-128", AffectedProduct: "Windows 10 for x64-based Systems", ComponentKB: "3116869", CVEs: "CVE-2015-6106"},
				{BulletinID: "ms15-128", AffectedProduct: "Windows 10 for x64-based Systems", AffectedComponent: "Microsoft .NET Framework 3.5", ComponentKB: "3116869", CVEs: "CVE-2015-6108"},
			},
		},
		{
			name: "row whose KB does not match an entry is passed through unchanged",
			in: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 7 for 32-bit Systems Service Pack 1", ComponentKB: "3109094", CVEs: "CVE-2015-6106"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 7 for 32-bit Systems Service Pack 1", ComponentKB: "3109094", CVEs: "CVE-2015-6106"},
			},
		},
		{
			name: "row that already has affected_component is passed through unchanged even if it matches the dispatch",
			in: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", AffectedComponent: "Microsoft .NET Framework 3.5", ComponentKB: "3116869", CVEs: "CVE-2015-6106,CVE-2015-6107,CVE-2015-6108"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", AffectedComponent: "Microsoft .NET Framework 3.5", ComponentKB: "3116869", CVEs: "CVE-2015-6106,CVE-2015-6107,CVE-2015-6108"},
			},
		},
		{
			name: "synth row is skipped when none of the entry's CVEs are present on the source row",
			in: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", ComponentKB: "3116869", CVEs: "CVE-2015-6106,CVE-2015-6107"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", ComponentKB: "3116869", CVEs: "CVE-2015-6106,CVE-2015-6107"},
			},
		},
		{
			name: "parseCVEs normalizes \"CVE-CVE-\" prefix duplication before comparison",
			in: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", ComponentKB: "3116869", CVEs: "CVE-CVE-2015-6106,CVE-2015-6107,CVE-CVE-2015-6108"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", ComponentKB: "3116869", CVEs: "CVE-2015-6106,CVE-2015-6107"},
				{BulletinID: "MS15-128", AffectedProduct: "Windows 10 for 32-bit Systems", AffectedComponent: "Microsoft .NET Framework 3.5", ComponentKB: "3116869", CVEs: "CVE-2015-6108"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bulletin.ApplyComponentReattributions(tt.in)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ApplyComponentReattributions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestApplyCVEAdditions(t *testing.T) {
	tests := []struct {
		name string
		in   []fetch.Bulletin
		want []fetch.Bulletin
	}{
		{
			name: "row without a bulletin entry is passed through unchanged",
			in: []fetch.Bulletin{
				{BulletinID: "MS15-097", ComponentKB: "3087039", CVEs: "CVE-2015-2506,CVE-2015-2507"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS15-097", ComponentKB: "3087039", CVEs: "CVE-2015-2506,CVE-2015-2507"},
			},
		},
		{
			name: "MS16-137 empty cves is filled with the bulletin's CVE set",
			in: []fetch.Bulletin{
				{BulletinID: "MS16-137", ComponentKB: "3198585", CVEs: ""},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS16-137", ComponentKB: "3198585", CVEs: "CVE-2016-7220,CVE-2016-7237,CVE-2016-7238"},
			},
		},
		{
			name: "idempotent: CVEs already present in row.CVEs are not duplicated",
			in: []fetch.Bulletin{
				{BulletinID: "MS16-137", ComponentKB: "3198585", CVEs: "CVE-2016-7220"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS16-137", ComponentKB: "3198585", CVEs: "CVE-2016-7220,CVE-2016-7237,CVE-2016-7238"},
			},
		},
		{
			name: "lowercase bulletin_id matches the dispatch case-insensitively",
			in: []fetch.Bulletin{
				{BulletinID: "ms16-137", ComponentKB: "3198510", CVEs: ""},
			},
			want: []fetch.Bulletin{
				{BulletinID: "ms16-137", ComponentKB: "3198510", CVEs: "CVE-2016-7220,CVE-2016-7237,CVE-2016-7238"},
			},
		},
		{
			name: "MS17-023 Flash Player CVEs added to empty cves row",
			in: []fetch.Bulletin{
				{BulletinID: "MS17-023", ComponentKB: "4014329", CVEs: ""},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS17-023", ComponentKB: "4014329", CVEs: "CVE-2017-2997,CVE-2017-2998,CVE-2017-2999,CVE-2017-3000,CVE-2017-3001,CVE-2017-3002,CVE-2017-3003"},
			},
		},
		{
			// parseCVEs explicitly canonicalises the lowercase "cve-" prefix
			// as a historical xlsx anomaly, so applyCVEAdditions must treat
			// lowercase row tokens as already-present and not append a
			// duplicate uppercase entry. The original lowercase token is
			// preserved verbatim; parseCVEs canonicalises it downstream.
			name: "idempotent: lowercase CVE token in row matches case-insensitively",
			in: []fetch.Bulletin{
				{BulletinID: "MS16-137", ComponentKB: "3198585", CVEs: "cve-2016-7220"},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS16-137", ComponentKB: "3198585", CVEs: "cve-2016-7220,CVE-2016-7237,CVE-2016-7238"},
			},
		},
		{
			// Whitespace around comma-separated tokens is allowed in xlsx
			// and TrimSpace'd before comparison; verify the dedup still
			// catches an existing token surrounded by extra whitespace.
			name: "idempotent: surrounding whitespace on existing token does not produce duplicate",
			in: []fetch.Bulletin{
				{BulletinID: "MS16-137", ComponentKB: "3198585", CVEs: "  CVE-2016-7220  "},
			},
			want: []fetch.Bulletin{
				{BulletinID: "MS16-137", ComponentKB: "3198585", CVEs: "  CVE-2016-7220  ,CVE-2016-7237,CVE-2016-7238"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bulletin.ApplyCVEAdditions(tt.in)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ApplyCVEAdditions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
