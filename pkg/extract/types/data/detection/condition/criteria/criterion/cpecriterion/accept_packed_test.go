package cpecriterion_test

import (
	"fmt"
	"testing"

	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// packedCriterion returns a chrome criterion with a semver Range and n
// packed entries shaped like NVD's chrome enumeration (four-segment
// versions, ANY elsewhere), and a pattern query that matches none of them,
// so that Accept decodes and relates every entry.
func packedCriterion(tb testing.TB, n int) (ccTypes.Criterion, ccTypes.Query) {
	tb.Helper()
	criterion := ccTypes.CPE("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*")
	ms := make([]ccTypes.CPE, 0, n)
	for i := range n {
		ms = append(ms, ccTypes.CPE(fmt.Sprintf("cpe:2.3:a:google:chrome:%d.0.%d.%d:*:*:*:*:*:*:*", 70+i/4000, 3000+(i/40)%1000, (i*7)%200)))
	}
	p, err := ccTypes.PackCPEMatches(criterion, ms)
	if err != nil {
		tb.Fatal(err)
	}
	c := ccTypes.Criterion{
		Vulnerable:       true,
		CPE:              criterion,
		Range:            &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "200.0.0.0"},
		CPEMatchesPacked: p,
	}
	return c, ccTypes.Query{CPE: "cpe:2.3:a:google:chrome:999.*:*:*:*:*:*:*:*"}
}

// TestCriterion_Accept_packedAllocations pins that decoding and relating a
// packed entry allocates nothing: the allocations of one Accept call do not
// grow with the number of packed entries. The constant per-call allocations
// (the WFNs, the warning) are not pinned, and the counts are compared with a
// slack: under the race detector a call costs 14 or 16 allocations at random,
// so AllocsPerRun reads one more or less between runs (observed in CI). The
// slack stays small: an allocation per entry adds thousands, but a slice or
// buffer re-grown across the 9,900 extra entries adds only 7 to 12.
func TestCriterion_Accept_packedAllocations(t *testing.T) {
	const slack = 2
	allocs := func(n int) float64 {
		c, q := packedCriterion(t, n)
		return testing.AllocsPerRun(10, func() {
			quality, _, err := c.Accept(q)
			if err != nil || quality != ccTypes.MatchQualityNone {
				t.Fatalf("Accept() = %v, %v; want %v, nil", quality, err, ccTypes.MatchQualityNone)
			}
		})
	}
	if small, large := allocs(100), allocs(10000); large > small+slack {
		t.Errorf("allocations per Accept grow with the packed entries: %v for 100, %v for 10000", small, large)
	}
}

// BenchmarkCriterion_Accept_packed measures Accept over a packed enumeration
// with a pattern query that matches nothing, which decodes every entry; the
// ns/entry metric is the per-entry cost. Compare runs with benchstat:
//
//	go test -run XXX -bench BenchmarkCriterion_Accept_packed -count 10 -cpu 1 ./pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/
func BenchmarkCriterion_Accept_packed(b *testing.B) {
	const n = 300000
	c, q := packedCriterion(b, n)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		quality, _, err := c.Accept(q)
		if err != nil || quality != ccTypes.MatchQualityNone {
			b.Fatalf("Accept() = %v, %v; want %v, nil", quality, err, ccTypes.MatchQualityNone)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/n, "ns/entry")
}
