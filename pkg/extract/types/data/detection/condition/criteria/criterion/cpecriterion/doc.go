// Package cpecriterion holds the CPE criterion of a detection condition and
// its evaluation against a query CPE (Accept): name matching per NISTIR
// 7696, the version Range, and the enumerations the criterion carries
// (CPEMatches, and CPEMatchesPacked for the names inside a Range).
//
// # Hot path
//
// Relating a pattern query to the packed enumeration runs once per packed
// entry, and the extracted NVD data holds about 51 million entries for
// google:chrome and 29 million for linux:linux_kernel, so a scan with one
// pattern query decodes and relates every one of them. The per-entry cost is
// about 55 ns and allocates nothing (it was 5 µs with go-cpe on the path, see
// #1006). The code on this path is reduced (packed.go), unbindReduced and
// unbindValueFS (wfn.go), overlaps (relation.go) and the packed loop of Accept
// (cpecriterion.go). A change to any of it keeps the path allocation-free per
// entry, which TestCriterion_Accept_packedAllocations pins, and is measured
// before and after with BenchmarkCriterion_Accept_packed, which no CI gates.
// Run it on an idle machine, from the repository root, on the base commit and
// on the change, and put the benchstat table in the PR description:
//
//	go test -run XXX -bench BenchmarkCriterion_Accept_packed -count 10 -cpu 1 ./pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/ > /tmp/old.txt
//	go test -run XXX -bench BenchmarkCriterion_Accept_packed -count 10 -cpu 1 ./pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/ > /tmp/new.txt
//	go run golang.org/x/perf/cmd/benchstat@latest /tmp/old.txt /tmp/new.txt
//
// A regression of a few ns per entry is a few seconds on a chrome scan.
package cpecriterion
