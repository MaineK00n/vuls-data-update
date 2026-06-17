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
		want    ccTypes.MatchQuality
		wantErr bool
	}{
		{
			name: "cpe in semver range -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "accept with target_sw in pattern, wildcard in query -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.8"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "different target_sw -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5:*:*:*:*:node.js:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "different part -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:vendor:product:1.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "query version wildcard with range -> Exact (query=ANY)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "version=* criterion, query version wildcard, no range -> Exact (all versions)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "concrete criterion, query version wildcard, no range -> Exact (query=ANY)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "version=* criterion with range, query version NA -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "1.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			name: "version=* criterion with range, concrete query out of range -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "criterion version NA, query version wildcard -> Exact (query=ANY)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "criterion version NA with range (range ignored), query wildcard -> Exact (query=ANY)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// version=NA fixes the product but not the version, so a concrete
			// scan version still matches at version-unconfirmed quality (e.g.
			// linux_kernel:- meaning "all versions" — go-cve-dictionary parity).
			name: "criterion version NA, concrete query -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			// A version=NA criterion still gates on non-version attributes:
			// a disjoint target_sw is not a match.
			name: "criterion version NA, disjoint target_sw -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:windows:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:linux:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "concrete criterion, no range, concrete query equal -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "concrete criterion with range, concrete query in range -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "concrete criterion with range, same concrete query out of range -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "concrete criterion, different concrete query: CPE attr disjoint (Range never consulted) -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:2.0.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "concrete criterion with range, query version ANY -> Exact (query=ANY)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "concrete criterion outside range, query version ANY short-circuits -> Exact (query=ANY)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "ge/lt range, query in range -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "ge/lt range, query below lower bound -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:0.9.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "cpe_matches: main CPE and every CPEMatches entry disjoint from query -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:15.4\\(3\\)m:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:other:product:1.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "cpe_matches: query matches one entry exactly via cpematch fallback -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:productX:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:productY:15.4\\(2\\)t1:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:productY:15.4\\(2\\)t1:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// go-cpe matching mis-classifies pairs of concrete values where one
			// trailing numeric segment is a numeric prefix of the other — e.g.
			// IsDisjoint("5.15.10", "5.15.103") returns false. The
			// concretelyDisjoint spot-check rescues the byte-wise truth so
			// the main CPE path does not falsely match.
			name: "go-cpe over-match guard: main CPE concrete-vs-concrete substring -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:linux:linux_kernel:5.15.103:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// Same over-match guard applied along the CPEMatches loop — a
			// cpematch entry "5.15.10" must NOT swallow a "5.15.103" query.
			name: "go-cpe over-match guard: CPEMatches concrete-vs-concrete substring -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:linux:linux_kernel:5.15.103:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// Non-semver query against a semver range: the comparator errors
			// (swallowed as non-match), and there is no RPM-style fallback.
			name: "non-semver query against semver range (compare error) -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "Range out, CPEMatches in: NVD listed an out-of-range version -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "Range in, CPEMatches non-matching: Range short-circuits -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "Range out, CPEMatches non-matching: neither narrowing matches -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:5.0.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "no narrowing: version=* pattern matches concrete query -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "different vendor -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:other:product:0.0.1:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "different product -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:other:0.0.1:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "pattern has target_sw, query has same target_sw -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:wordpress:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "pattern has sw_edition, query has wildcard -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:enterprise:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "FixStatus + Fixed are metadata: in-range query still Exact",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed, Vendor: "vendor"},
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				Fixed:      []string{"2.0.0", "2.0.1"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "FixStatus + Fixed are metadata: query matching a Fixed entry still None if Range excludes it",
			fields: fields{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed, Vendor: "vendor"},
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				Fixed:      []string{"2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:2.0.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "non-semver Range stored as-is, CPEMatches covers the enumerated version -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeUnknown, LessThan: "15.4(3)m"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
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
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "pan-os hotfix query, escaped version, at exclusive upper bound",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypePANOS, GreaterEqual: "10.1.0", LessThan: "10.1.14-h13"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.14-h13:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
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
				t.Errorf("Accept() = %s, want %s", got, tt.want)
			}
		})
	}
}
