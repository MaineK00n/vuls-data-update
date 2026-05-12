package bulletin_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

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

func Test_collectIECumChainEdges(t *testing.T) {
	type chainEdge struct {
		Old string
		New string
	}

	// writeBulletinFile writes a minimal bulletin JSON to dir/name.json so the
	// test exercises collectIECumChainEdges without coupling to large fixtures.
	type bulletinRow struct {
		Title            string `json:"title"`
		DatePosted       string `json:"date_posted"`
		BulletinID       string `json:"bulletin_id"`
		AffectedProduct  string `json:"affected_product"`
		AffectedComponent string `json:"affected_component"`
		ComponentKB      string `json:"component_kb"`
	}

	writeFile := func(t *testing.T, path string, rows []bulletinRow) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	flatten := func(edges map[string]map[string]struct{}) []chainEdge {
		var out []chainEdge
		for old, news := range edges {
			for n := range news {
				out = append(out, chainEdge{Old: old, New: n})
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Old != out[j].Old {
				return out[i].Old < out[j].Old
			}
			return out[i].New < out[j].New
		})
		return out
	}

	tests := []struct {
		name  string
		files map[string][]bulletinRow
		want  []chainEdge
	}{
		{
			name: "two consecutive IE Cum bulletins same product+component → one edge",
			files: map[string][]bulletinRow{
				"16/MS16-118.json": {{
					Title:             "Cumulative Security Update for Internet Explorer",
					DatePosted:        "[$-10009]10/11/2016",
					BulletinID:        "MS16-118",
					AffectedProduct:   "Windows 8.1 for x64-based Systems",
					AffectedComponent: "Internet Explorer 11",
					ComponentKB:       "3192392",
				}},
				"16/MS16-142.json": {{
					Title:             "Cumulative Security Update for Internet Explorer",
					DatePosted:        "[$-10009]11/8/2016",
					BulletinID:        "MS16-142",
					AffectedProduct:   "Windows 8.1 for x64-based Systems",
					AffectedComponent: "Internet Explorer 11",
					ComponentKB:       "3197873",
				}},
			},
			want: []chainEdge{{Old: "3192392", New: "3197873"}},
		},
		{
			name: "different (product, component) groups chain independently",
			files: map[string][]bulletinRow{
				"16/MS16-118.json": {
					{
						Title:             "Cumulative Security Update for Internet Explorer",
						DatePosted:        "[$-10009]10/11/2016",
						BulletinID:        "MS16-118",
						AffectedProduct:   "Windows 8.1 for x64-based Systems",
						AffectedComponent: "Internet Explorer 11",
						ComponentKB:       "3192392",
					},
					{
						Title:             "Cumulative Security Update for Internet Explorer",
						DatePosted:        "[$-10009]10/11/2016",
						BulletinID:        "MS16-118",
						AffectedProduct:   "Windows 7 for x64-based Systems Service Pack 1",
						AffectedComponent: "Internet Explorer 11",
						ComponentKB:       "3192391",
					},
				},
				"16/MS16-142.json": {
					{
						Title:             "Cumulative Security Update for Internet Explorer",
						DatePosted:        "[$-10009]11/8/2016",
						BulletinID:        "MS16-142",
						AffectedProduct:   "Windows 8.1 for x64-based Systems",
						AffectedComponent: "Internet Explorer 11",
						ComponentKB:       "3197873",
					},
					{
						Title:             "Cumulative Security Update for Internet Explorer",
						DatePosted:        "[$-10009]11/8/2016",
						BulletinID:        "MS16-142",
						AffectedProduct:   "Windows 7 for x64-based Systems Service Pack 1",
						AffectedComponent: "Internet Explorer 11",
						ComponentKB:       "3197867",
					},
				},
			},
			want: []chainEdge{
				{Old: "3192391", New: "3197867"},
				{Old: "3192392", New: "3197873"},
			},
		},
		{
			name: "non-IE-Cum bulletins are ignored",
			files: map[string][]bulletinRow{
				"17/MS17-023.json": {{
					Title:             "Security Update for Adobe Flash Player",
					DatePosted:        "[$-10009]3/14/2017",
					BulletinID:        "MS17-023",
					AffectedProduct:   "Windows 10",
					AffectedComponent: "Adobe Flash Player",
					ComponentKB:       "4014329",
				}},
				"16/MS16-118.json": {{
					Title:             "Cumulative Security Update for Internet Explorer",
					DatePosted:        "[$-10009]10/11/2016",
					BulletinID:        "MS16-118",
					AffectedProduct:   "Windows 8.1 for x64-based Systems",
					AffectedComponent: "Internet Explorer 11",
					ComponentKB:       "3192392",
				}},
			},
			want: nil,
		},
		{
			name: "older 'Security Update for Internet Explorer' title is also chained",
			files: map[string][]bulletinRow{
				"14/MS14-021.json": {{
					Title:             "Security Update for Internet Explorer",
					DatePosted:        "[$-10009]5/1/2014",
					BulletinID:        "MS14-021",
					AffectedProduct:   "Windows 7 for x64-based Systems Service Pack 1",
					AffectedComponent: "Internet Explorer 11",
					ComponentKB:       "2964358",
				}},
				"14/MS14-029.json": {{
					Title:             "Cumulative Security Update for Internet Explorer",
					DatePosted:        "[$-10009]5/13/2014",
					BulletinID:        "MS14-029",
					AffectedProduct:   "Windows 7 for x64-based Systems Service Pack 1",
					AffectedComponent: "Internet Explorer 11",
					ComponentKB:       "2953522",
				}},
			},
			want: []chainEdge{{Old: "2964358", New: "2953522"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, rows := range tt.files {
				writeFile(t, filepath.Join(dir, name), rows)
			}
			got, err := bulletin.CollectIECumChainEdges(dir)
			if err != nil {
				t.Fatalf("CollectIECumChainEdges() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, flatten(got)); diff != "" {
				t.Errorf("(-expected +got):\n%s", diff)
			}
		})
	}
}
