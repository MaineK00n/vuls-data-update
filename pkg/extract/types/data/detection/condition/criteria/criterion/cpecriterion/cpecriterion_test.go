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
			// A partial wildcard in the query version ("12.*", unquoted "*")
			// is a legitimate CPE name-matching pattern (NIST IR 7696): it is
			// a superset of every concrete "12.x", so a concrete criterion it
			// covers is accepted on attribute match alone.
			name: "concrete criterion, query version partial wildcard covering it, no range -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.3:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "concrete criterion, query version partial wildcard not covering it, no range -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:13.0:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// The same pattern matching applies along the CPEMatches
			// enumeration (a non-semver range's concrete list).
			name: "CPEMatches-only criterion, query version partial wildcard covering an entry -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:12.0:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:12.4:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// A Range is consulted only for a concrete query; a pattern query
			// is evaluated by name against the CPEMatches enumeration alone.
			name: "range criterion, query version partial wildcard, covered by a CPEMatches entry -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "14.23"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:12.0:beta1:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "range criterion, query version partial wildcard, no CPEMatches entry covered -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "14.23"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:12.0:beta1:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:15.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// The pattern denotes versions the Range would accept, but a
			// Range is never evaluated against a pattern: without an
			// enumerated name there is nothing for the pattern to match.
			name: "range-only criterion (no CPEMatches), query version partial wildcard inside the range -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "14.23"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// A pattern in the criterion VERSION is undefined under NISTIR
			// 7696 Table 6-2 (target-side wild cards) and is related as the
			// set it denotes, like any criterion-side pattern: a concrete
			// query it contains is Exact, one it does not is None.
			name: "criterion version partial wildcard, concrete query it covers -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.3:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "criterion version partial wildcard, concrete query it does not cover -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:13.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "criterion version partial wildcard, query version ANY -> Exact (query=ANY)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// Patterns on both sides (Table 6-2 row 17, undefined) are related
			// as the sets they denote: any intersection is Exact, whichever
			// side contains the other or neither does, ...
			name: "criterion version partial wildcard, identical query pattern -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "criterion version partial wildcard, narrower query pattern -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.3*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "criterion version partial wildcard, wider query pattern -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "criterion version partial wildcard, partially overlapping query pattern -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*.3:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// A wild card right after an escaped backslash is unquoted (an
			// even number of backslashes precede it), so this query is a
			// pattern and never reaches the Range, whose unsupported type
			// would otherwise make Accept fail. go-cpe's ContainsWildcards
			// would call the query concrete and route it to the Range.
			name: "pattern query after an escaped backslash skips the Range (unsupported type) -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeType("unsupported"), LessThan: "2.0"},
			},
			args: args{query: ccTypes.Query{CPE: `cpe:2.3:a:vendor:product:a\\*:*:*:*:*:*:*:*`}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// ... and disjoint sets are None.
			name: "criterion version partial wildcard, disjoint query pattern -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:13.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "criterion version partial wildcard, disjoint target_sw -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:12.*:*:*:*:*:linux:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.3:*:*:*:*:windows:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// Same handling for a CPEMatches entry whose version is a pattern.
			name: "CPEMatches entry partial wildcard, concrete query it covers -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.3:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "CPEMatches entry partial wildcard, concrete query it does not cover -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:13.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "CPEMatches entry partial wildcard, wider query pattern -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "CPEMatches entry partial wildcard, disjoint query pattern -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:13.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// An NA entry in the enumeration is treated like an NA criterion
			// (the NA column of the version table): the product matched, the
			// version cannot be evaluated.
			name: "CPEMatches NA entry only, concrete query -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "12.0"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.3:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			name: "CPEMatches NA entry only, query pattern -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			name: "CPEMatches NA entry with disjoint target_sw, concrete query -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:linux:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:-:*:*:*:*:linux:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.3:*:*:*:*:windows:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// The strongest entry wins regardless of order: the NA entry
			// yields VersionUnconfirmed, the concrete one Exact.
			name: "CPEMatches NA entry then concrete entry equal to the query -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:12.3:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.3:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// A version spelled "NA" is a concrete string, not the logical
			// value "-" (GetString renders both as "NA"): it neither relaxes
			// to VersionUnconfirmed ...
			name: "CPEMatches entry whose version is the literal string NA, concrete query -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:NA:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "criterion version is the literal string NA, concrete query -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:NA:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// ... nor is it a version-less query.
			name: "query version is the literal string NA, concrete criterion -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:NA:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "CPEMatches entry partial wildcard, query version ANY -> Exact (query=ANY)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "14.23"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// Every entry the query pattern intersects is Exact, a pattern
			// entry narrower than the query as much as a concrete one inside
			// it; the enumeration is a union, so the first overlap wins.
			name: "CPEMatches narrower pattern entry then concrete entry inside the query pattern -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:12.3*:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:12.4:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:12.*:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// Name matching is case-insensitive (NISTIR 7696 §6.2); the
			// byte-wise concretelyDisjoint guard that used to reject this is
			// gone.
			name: "concrete criterion, concrete query differing only in case -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0A:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0a:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "concrete criterion, query product differing only in case -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:PRODUCT:1.0:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// A criterion-side pattern on a non-version attribute is related
			// as the set it denotes (Table 6-2, row 14, undefined with the
			// query as the source), so it covers a concrete query value ...
			name: "criterion target_sw pattern covering the query target_sw -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows_10:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// ... and is DISJOINT from NA (row 16): a pattern never matches
			// "-". (go-cpe's matching reported this pair as UNDEFINED, which
			// the old overlaps test let through.)
			name: "criterion target_sw pattern, query target_sw NA -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:-:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// Patterns on both sides are undefined either way (row 17) and are
			// related as the sets they denote; on a non-version attribute any
			// intersection is compatible, so only disjoint patterns are None.
			name: "criterion and query target_sw both patterns, query within the criterion -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows_1*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "criterion and query target_sw both patterns, identical -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "criterion and query target_sw both patterns, partially overlapping -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*_10:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "criterion and query target_sw both patterns, disjoint -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:linux*:*:*"}},
			want: ccTypes.MatchQualityNone,
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
			name: "criterion version NA with range (range ignored), query NA -> Exact (NA vs NA is EQUAL)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// Non-version SUBSET/SUPERSET does not demote the NA/NA pair, as
			// for every other Exact path (e.g. a concrete target_sw against
			// a wildcard one).
			name: "criterion version NA with target_sw, query NA with wildcard target_sw -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:windows:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// A concrete version is DISJOINT from NA under CPE name matching, but the
			// scan simply has no version to evaluate: the mirror of an NA criterion
			// against a concrete scan.
			name: "concrete criterion, no range, query NA -> VersionUnconfirmed (no version to evaluate)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			name: "concrete criterion, query NA, disjoint target_sw -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:linux:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// The NVD cpematch-expanded shape: a version=* criterion narrowed only by
			// an enumeration. An NA entry matches an NA scan, as the main CPE would.
			name: "version=* criterion, cpematches NA entry, query NA -> Exact (NA vs NA is EQUAL)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "version=* criterion, cpematches * entry, query NA -> Exact (* is a SUPERSET of NA)",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "version=* criterion, cpematches concrete entries only, query NA -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			name: "version=* criterion with range, cpematches NA entry, query NA -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "1.0.0"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// A version=NA query reaches the entries on its own even when the main
			// CPE is disjoint (here target_sw differs).
			name: "main CPE disjoint, cpematches NA entry, query NA -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:windows:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:-:*:*:*:*:linux:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:linux:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "main CPE disjoint, cpematches concrete entry, query NA -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:linux:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:linux:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			name: "concrete criterion with range, query NA -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			name: "version=* criterion with range, cpematches concrete entries only, query NA -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:3.0:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			// Sort() order: a * entry ahead of an NA entry must not hide it.
			name: "main CPE disjoint, cpematches * then NA entry, query NA -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:*:*:*:*:*:linux:*:*",
					"cpe:2.3:a:vendor:product:-:*:*:*:*:linux:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:linux:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// A wildcard pattern is neither NA nor *: DISJOINT from NA under
			// CPE name matching, so it is not an exact match.
			name: "wildcard-pattern criterion version, query NA -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.*:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			name: "wildcard-pattern cpematches entry, query NA -> VersionUnconfirmed",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendor:product:1.*:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityVersionUnconfirmed,
		},
		{
			name: "main CPE and cpematches entries disjoint beyond the version, query NA -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows:*:*",
				CPEMatches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:-:*:*:*:*:windows:*:*",
					"cpe:2.3:a:vendor:product:1.0:*:*:*:*:windows:*:*",
				},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:linux:*:*"}},
			want: ccTypes.MatchQualityNone,
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
			// NA vs NA is EQUAL under CPE name matching: a genuinely
			// version-less product scanned as such is a confident match.
			name: "criterion version NA, query version NA -> Exact",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:vendor:product_firmware:-:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:vendor:product_firmware:-:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			name: "criterion version NA, query version NA, disjoint update -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:vendor:product:-:sp1:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:vendor:product:-:sp2:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
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
			// go-cpe before knqyf263/go-cpe#9 mis-classified pairs of concrete
			// values where one trailing numeric segment is a numeric prefix of
			// the other: IsDisjoint(source "5.15.10", target "5.15.103")
			// returned false, and Accept once relied on it (with the query as
			// the source, so the over-match fired for a scanned "5.15.10"
			// against a "5.15.103" criterion). Name matching no longer goes
			// through go-cpe's matching package; pinned in both directions so
			// the comparator never regresses to that behaviour.
			name: "go-cpe over-match regression: main CPE, query is a numeric prefix of the criterion -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:linux:linux_kernel:5.15.103:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "go-cpe over-match regression: main CPE, criterion is a numeric prefix of the query -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*",
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:linux:linux_kernel:5.15.103:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// Same regression pinned along the CPEMatches loop, in both
			// directions.
			name: "go-cpe over-match regression: CPEMatches, query is a numeric prefix of the entry -> None",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
				CPEMatches: []ccTypes.CPE{"cpe:2.3:o:linux:linux_kernel:5.15.103:*:*:*:*:*:*:*"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			name: "go-cpe over-match regression: CPEMatches, entry is a numeric prefix of the query -> None",
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
			// The query carries the hotfix in the VERSION attribute
			// ("10.1.14-h11"). That is the form the vuls snmp2cpe scanner emits;
			// NVD- and cisco-provided CPEs instead put the hotfix in the UPDATE
			// attribute (":h11:"). go-cpe escapes the dots and hyphen of the
			// version-attribute form in the WFN ("10\.1\.14\-h11"), so Accept
			// must unescape it before the pan-os comparator runs, otherwise the
			// escaped query never matches.
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
		{
			// The query carries the hotfix in the UPDATE attribute instead
			// (NVD/cisco form: version="10.1.14", update="h11"). Accept folds a
			// hotfix-looking UPDATE into the version for pan-os ranges, so this
			// resolves to 10.1.14-h11 and is correctly in range.
			name: "pan-os hotfix query, update attribute, within range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypePANOS, GreaterEqual: "10.1.0", LessThan: "10.1.14-h13"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.14:h11:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// Same UPDATE-attribute form at the exclusive hotfix upper bound: the
			// device is fixed (10.1.14-h13), so without folding UPDATE the query
			// would read as base 10.1.14 (< 10.1.14-h13) and falsely match.
			name: "pan-os hotfix query, update attribute, at exclusive upper bound",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypePANOS, GreaterEqual: "10.1.0", LessThan: "10.1.14-h13"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.14:h13:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityNone,
		},
		{
			// Uppercase UPDATE hotfix ("H11"): the fold lowercases it to the
			// "-h11" form the comparator requires (it rejects "-H11"), so it
			// still resolves to 10.1.14-h11 and is in range.
			name: "pan-os hotfix query, uppercase update attribute, within range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypePANOS, GreaterEqual: "10.1.0", LessThan: "10.1.14-h13"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.14:H11:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
		},
		{
			// The hotfix is already in the version AND a hotfix-looking UPDATE is
			// also present: do not fold (that would build an unparseable
			// "10.1.14-h11-h11"); the version form alone is in range.
			name: "pan-os hotfix in version, hotfix update attribute, no double-fold",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
				Range:      &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypePANOS, GreaterEqual: "10.1.0", LessThan: "10.1.14-h13"},
			},
			args: args{query: ccTypes.Query{CPE: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.14-h11:h11:*:*:*:*:*:*"}},
			want: ccTypes.MatchQualityExact,
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
