package cpecriterion_test

import (
	"testing"

	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
)

func TestCriterion_Accept(t *testing.T) {
	type fields struct {
		Vulnerable bool
		FixStatus  *fixstatusTypes.FixStatus
		CPE        ccTypes.CPE
		Range      *ccRangeTypes.Range
		CPEMatches []ccTypes.CPE
		Fixed      []string
	}
	type args struct {
		query ccTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "cpe in semver range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "accept with target_sw in pattern, wildcard in query",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.8"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "not accept with different target_sw",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5:*:*:*:*:node.js:*:*"}},
			want: false,
		},
		{
			name: "not accept with different part",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:vendor:product:1.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "query version wildcard with range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "query version wildcard without range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "query version wildcard against specific pattern version",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern version ANY, query version NA",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "1.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern version ANY, query version not in range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "pattern version NA",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern version NA with range, range is ignored",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern specific version with range, query same version in range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern specific version with range, query same version out of range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "pattern specific version, query different specific version: CPE attr disjoint (Range never consulted)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:2.0.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "pattern specific version with range, query version ANY",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern specific version outside range, query version ANY short-circuits",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "ge/lt range, query in range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "ge/lt range, query below lower bound",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:0.9.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "cpe_matches: main CPE and every CPEMatches entry disjoint from query → false",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:15.4\\(3\\)m:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:other:product:1.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "cpe_matches: query matches one entry exactly via cpematch fallback",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:productX:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:productY:15.4\\(2\\)t1:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:productY:15.4\\(2\\)t1:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			// go-cpe matching mis-classifies pairs of concrete values where one
			// trailing numeric segment is a numeric prefix of the other — e.g.
			// IsDisjoint("5.15.10", "5.15.103") returns false. The
			// concretelyDisjoint spot-check rescues the byte-wise truth so
			// the main CPE path does not falsely match.
			name: "go-cpe over-match guard: main CPE concrete-vs-concrete substring → false",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:linux:linux_kernel:5.15.103:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			// Same over-match guard applied along the CPEMatches loop — a
			// cpematch entry "5.15.10" must NOT swallow a "5.15.103" query.
			name: "go-cpe over-match guard: CPEMatches concrete-vs-concrete substring → false",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:linux:linux_kernel:5.15.103:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "unparseable query version with range yields false",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "Range out, CPEMatches in: NVD listed an out-of-range version",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "Range in, CPEMatches non-matching: Range short-circuits",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "Range out, CPEMatches non-matching: neither narrowing matches",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:5.0.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "accept (no narrowing): wildcard pattern matches concrete query",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "different vendor",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:other:product:0.0.1:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "different product",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:other:0.0.1:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "pattern has target_sw, query has same target_sw",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:wordpress:*:*"}},
			want: true,
		},
		{
			name: "pattern has sw_edition, query has wildcard",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:enterprise:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "FixStatus + Fixed are metadata: in-range query still accepted",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed, Vendor: "vendor"},
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				Fixed:      []string{"2.0.0", "2.0.1"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "FixStatus + Fixed are metadata: query matching a Fixed entry is still rejected if Range excludes it",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed, Vendor: "vendor"},
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				Fixed:      []string{"2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:2.0.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "non-semver Range stored as-is, CPEMatches covers all enumerated versions",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeUnknown, LessThan: "15.4(3)m"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			// go-cpe escapes the dots and hyphen of a PAN-OS hotfix version in
			// the WFN ("10\.1\.14\-h11"); Accept must unescape it before the
			// pan-os comparator runs, otherwise the escaped query never matches.
			name: "pan-os hotfix query, escaped version, within range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypePANOS, GreaterEqual: "10.1.0", LessThan: "10.1.14-h13"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.14-h11:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pan-os hotfix query, escaped version, at exclusive upper bound",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypePANOS, GreaterEqual: "10.1.0", LessThan: "10.1.14-h13"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.14-h13:*:*:*:*:*:*:*"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ccTypes.Criterion{
				Vulnerable: tt.fields.Vulnerable,
				FixStatus:  tt.fields.FixStatus,
				CPE:        tt.fields.CPE,
				Range:      tt.fields.Range,
				CPEMatches: tt.fields.CPEMatches,
				Fixed:      tt.fields.Fixed,
			}
			got, err := c.Accept(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}


