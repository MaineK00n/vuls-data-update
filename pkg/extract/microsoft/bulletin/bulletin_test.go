package bulletin_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/bulletin"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
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

// TestIECumChainEdges verifies known edges in the static ieCumChainEdges map.
// The map is exhaustively generated from the frozen Bulletin corpus, so any
// regression in its structure (e.g., missing edges across the Nov 2016 MS16-142
// gap that A1 was specifically designed to bridge) should fail this test.
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
			news, ok := bulletin.IECumChainEdges[tt.oldKBID]
			if !ok {
				t.Fatalf("ieCumChainEdges has no entry for KB%s", tt.oldKBID)
			}
			if !slices.Contains(news, tt.newKBID) {
				t.Errorf("ieCumChainEdges[%q] = %v, want to contain %q", tt.oldKBID, news, tt.newKBID)
			}
		})
	}
}

// TestBulletinArchiveSupersedes verifies known edges in the static
// bulletinArchiveSupersedes map. The map captures supersedes that the frozen
// BulletinSearch.xlsx omits but the Microsoft Learn bulletin archive records,
// so any regression in its structure should fail this test.
func TestBulletinArchiveSupersedes(t *testing.T) {
	tests := []struct {
		name    string
		oldKBID string
		newKBID string
	}{
		{
			name:    "MS13-054 Lync 2010 Attendee user install: 2827751 → 2843162 (Excel attributed Lync admin KB instead)",
			oldKBID: "2827751",
			newKBID: "2843162",
		},
		{
			name:    "MS13-054 Lync 2010 Attendee admin install: 2827752 → 2843163",
			oldKBID: "2827752",
			newKBID: "2843163",
		},
		{
			name:    "MS14-029 IE Win Server: 2936068 → 2953522 (Excel missed)",
			oldKBID: "2936068",
			newKBID: "2953522",
		},
		{
			name:    "MS14-035 IE Cum May → Jun via 2957689 → 2962872 (chain continuation Excel split)",
			oldKBID: "2957689",
			newKBID: "2962872",
		},
		{
			name:    "MS16-144 IE 9 Cumulative (Vista SP2): 3197655 → 3203621",
			oldKBID: "3197655",
			newKBID: "3203621",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			news, ok := bulletin.BulletinArchiveSupersedes[tt.oldKBID]
			if !ok {
				t.Fatalf("bulletinArchiveSupersedes has no entry for KB%s", tt.oldKBID)
			}
			if !slices.Contains(news, tt.newKBID) {
				t.Errorf("bulletinArchiveSupersedes[%q] = %v, want to contain %q", tt.oldKBID, news, tt.newKBID)
			}
		})
	}
}

// TestBulletinArchiveSupersedesOverride verifies known entries in the static
// bulletinArchiveSupersedesOverride map. These are KB pairs where the frozen
// BulletinSearch.xlsx Supersedes column attributes the supersedes to the
// wrong component_kb (Excel mis-attribution); the Microsoft Learn archive
// records a different ancestry. Each test asserts that the override would
// remove the wrong edge.
//
// End-to-end coverage of the deletion loop in extract() is provided by the
// MS13-054 fixture (testdata/fixtures/13/MS13-054.json): its two rows are
// the Lync 2010 Attendee user/admin install components (KB2843162/2843163)
// whose Excel-cited supersedes (MS13-041[2827750]) is dropped by this
// override map and whose correct supersedes (KB2827751/2827752) is then
// added by bulletinArchiveSupersedes. The TestExtract golden run asserts
// the resulting microsoftkb files contain only the corrected edges and
// that KB2827750 does not surface (no remaining inbound edges).
func TestBulletinArchiveSupersedesOverride(t *testing.T) {
	tests := []struct {
		name    string
		newKBID string
		oldKBID string
	}{
		{
			name:    "MS13-054 Lync 2010 Attendee user install (2843162): drop wrong edge from KB2827750 (which actually fixes the 64-bit pkg)",
			newKBID: "2843162",
			oldKBID: "2827750",
		},
		{
			name:    "MS13-054 Lync 2010 Attendee admin install (2843163): drop wrong edge from KB2827750",
			newKBID: "2843163",
			oldKBID: "2827750",
		},
		{
			name:    "MS15-062 ADFS (3062577): drop self-supersedes (Excel claims KB3062577 supersedes itself)",
			newKBID: "3062577",
			oldKBID: "3062577",
		},
		{
			name:    "MS16-054 Word 2016 (3115094): drop wrong edge from KB3142577 (Excel cited a later unrelated KB)",
			newKBID: "3115094",
			oldKBID: "3142577",
		},
		{
			name:    "MS16-054 Word 2016 (3115094): drop wrong edge from KB3154208",
			newKBID: "3115094",
			oldKBID: "3154208",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			olds, ok := bulletin.BulletinArchiveSupersedesOverride[tt.newKBID]
			if !ok {
				t.Fatalf("bulletinArchiveSupersedesOverride has no entry for KB%s", tt.newKBID)
			}
			if !slices.Contains(olds, tt.oldKBID) {
				t.Errorf("bulletinArchiveSupersedesOverride[%q] = %v, want to contain %q", tt.newKBID, olds, tt.oldKBID)
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
		// — its NA cells are captured by KB-keyed entries in
		// bulletinArchiveKBNotApplicable (KB923088/923089/923090/924998/924999),
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bulletin.NormalizeArchiveComponentKey(tt.args.bulletinID, tt.args.product, tt.args.component); got != tt.want {
				t.Errorf("normalizeArchiveComponentKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBulletinArchiveNotApplicable verifies known entries in the two static
// maps used to correct Excel's lossy per-CVE attribution. Both maps are
// regenerated from the frozen Bulletin archive markdown corpus (1554
// bulletins, retired April 2017), so any regression in their structure
// (e.g., a generator change dropping a recognized header label, or
// stripping a CVE attribution) should fail this test. End-to-end coverage
// that the filter actually drops the over-attributed CVEs is provided by
// the MS14-010 golden test.
func TestBulletinArchiveNotApplicable(t *testing.T) {
	t.Run("KB-keyed", func(t *testing.T) {
		tests := []struct {
			name        string
			componentKB string
			cve         string
		}{
			{
				name:        "MS16-007 KB3108664 NA for CVE-2016-0019 (per-CVE columns under \"Operating System\" header)",
				componentKB: "3108664",
				cve:         "CVE-2016-0019",
			},
			{
				name:        "MS13-040 KB2804576 (.NET 4) NA for CVE-2013-1337 (under \"Affected Software\" header)",
				componentKB: "2804576",
				cve:         "CVE-2013-1337",
			},
			// MS06-060 NA via KB-keyed. KB923089 is shared by Word 2002 SP3 +
			// Works Suite 2004/2005/2006 — per the Microsoft footnote "Works
			// Suite severity = Word 2002 severity", so the Word 2002 column's
			// NA cell drops CVE-2006-4693 from all four rows simultaneously.
			{
				name:        "MS06-060 KB923089 (Word 2002 SP3 + Works Suite 2004/2005/2006) NA for CVE-2006-4693",
				componentKB: "923089",
				cve:         "CVE-2006-4693",
			},
			{
				name:        "MS06-060 KB924998 (Office v. X for Mac) NA for CVE-2006-3651 (Word for Mac column)",
				componentKB: "924998",
				cve:         "CVE-2006-3651",
			},
			{
				name:        "MS06-060 KB924999 (Word 2004 for Mac) NA for CVE-2006-4534 (Word for Mac column)",
				componentKB: "924999",
				cve:         "CVE-2006-4534",
			},
			{
				name:        "MS13-004 KB2742613 (.NET 4.5) NA for CVE-2013-0001 (explicit \"Not applicable\" cell; KB appears as \"(KB2742613)\" — covered by extended regex)",
				componentKB: "2742613",
				cve:         "CVE-2013-0001",
			},
			{
				name:        "MS16-106 KB3185911 NA for CVE-2016-3356 (markdown uses \"Not applicable\" — uniformly NA across all 19 xlsx rows of this shared KB)",
				componentKB: "3185911",
				cve:         "CVE-2016-3356",
			},
			{
				name:        "MS16-106 KB3189866 (Windows 10 Version 1607) NA for CVE-2016-3349 (markdown uses \"Not affected\" — exercises the legacy-marker predicate; uniformly NA across both xlsx rows of this shared KB)",
				componentKB: "3189866",
				cve:         "CVE-2016-3349",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cves, ok := bulletin.BulletinArchiveKBNotApplicable[tt.componentKB]
				if !ok {
					t.Fatalf("bulletinArchiveKBNotApplicable has no entry for KB%s", tt.componentKB)
				}
				if !slices.Contains(cves, tt.cve) {
					t.Errorf("bulletinArchiveKBNotApplicable[%q] = %v, want to contain %q", tt.componentKB, cves, tt.cve)
				}
			})
		}
	})
	t.Run("Component-keyed", func(t *testing.T) {
		tests := []struct {
			name       string
			bulletinID string
			component  string
			cve        string
		}{
			{
				name:       "MS16-037 IE 11 NA for CVE-2016-0159 (IE Cumulative, CVE-rows × IE-version cols)",
				bulletinID: "MS16-037",
				component:  "Internet Explorer 11",
				cve:        "CVE-2016-0159",
			},
			{
				name:       "MS14-010 IE 11 NA for CVE-2014-0269 (IE Cumulative, verified by golden diff)",
				bulletinID: "MS14-010",
				component:  "Internet Explorer 11",
				cve:        "CVE-2014-0269",
			},
			{
				name:       "MS06-012 PowerPoint 2000 NA for CVE-2005-4131 (Office cross-product table)",
				bulletinID: "MS06-012",
				component:  "Microsoft PowerPoint 2000",
				cve:        "CVE-2005-4131",
			},
			{
				name:       "MS06-020 Win 2000 NA for CVE-2006-0024 (no current Excel row triggers; kept for completeness)",
				bulletinID: "MS06-020",
				component:  "Windows 2000",
				cve:        "CVE-2006-0024",
			},
			{
				name:       "MS06-039 Project 2000 NA for CVE-2006-0033",
				bulletinID: "MS06-039",
				component:  "Microsoft Project 2000",
				cve:        "CVE-2006-0033",
			},
			// MS06-060 NA cells are encoded in bulletinArchiveKBNotApplicable
			// (KB-keyed), not here. See the corresponding KB-keyed test cases.
			{
				name:       "MS06-078 WMP 6.4 NA for CVE-2006-6134",
				bulletinID: "MS06-078",
				component:  "Windows Media Player 6.4 (All operating systems)",
				cve:        "CVE-2006-6134",
			},
			// Product-keyed mixed-applicability cases: the KB is shared across
			// xlsx rows whose per-CVE table cells differ in NA status, so the
			// filter dispatches on affected_product unchanged.
			{
				name:       "MS16-106 Windows Server 2008 NA for CVE-2016-3349 (KB3185911 shared with Win 8.1+ where the CVE is applicable)",
				bulletinID: "MS16-106",
				component:  "Windows Server 2008 for 32-bit Systems Service Pack 2",
				cve:        "CVE-2016-3349",
			},
			// MS15-128's KB3109094 and KB3116869 both span multiple Format A
			// tables of the bulletin (OS-level + .NET Framework component),
			// so neither KB-keyed nor product-keyed dispatch can safely
			// filter the mixed-applicability cells — they are intentionally
			// not represented in either map. The over-attribution FP
			// persists as a known trade-off; see mixedProductKeyedBulletins
			// in bulletin.go for the rationale.
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				perComp, ok := bulletin.BulletinArchiveComponentNotApplicable[tt.bulletinID]
				if !ok {
					t.Fatalf("bulletinArchiveComponentNotApplicable has no entry for %s", tt.bulletinID)
				}
				cves, ok := perComp[tt.component]
				if !ok {
					t.Fatalf("bulletinArchiveComponentNotApplicable[%q][%q] missing", tt.bulletinID, tt.component)
				}
				if !slices.Contains(cves, tt.cve) {
					t.Errorf("bulletinArchiveComponentNotApplicable[%q][%q] = %v, want to contain %q", tt.bulletinID, tt.component, cves, tt.cve)
				}
			})
		}
	})
}

// TestBulletinArchiveCVECorrections verifies known entries in the static
// bulletinArchiveCVECorrections map. The map captures per-bulletin
// BulletinSearch.xlsx CVE tokens that do not appear in the bulletin's
// archive markdown, mapped either to a remapped canonical CVE (non-empty
// fix) or to a drop action (empty fix). Both branches are exercised below.
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
			perBulletin, ok := bulletin.BulletinArchiveCVECorrections[tt.bulletinID]
			if !ok {
				if tt.wantOK {
					t.Fatalf("bulletinArchiveCVECorrections has no entry for %s", tt.bulletinID)
				}
				return
			}
			fix, ok := perBulletin[tt.token]
			if ok != tt.wantOK {
				t.Errorf("bulletinArchiveCVECorrections[%q][%q] ok = %v, want %v", tt.bulletinID, tt.token, ok, tt.wantOK)
			}
			if fix != tt.wantFix {
				t.Errorf("bulletinArchiveCVECorrections[%q][%q] = %q, want %q", tt.bulletinID, tt.token, fix, tt.wantFix)
			}
		})
	}
}
