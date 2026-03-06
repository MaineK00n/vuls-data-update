package amazon_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/amazon"
)

// TestNeedsKernel612Guard asserts that every advisory ID in the kernel6.12 guard
// list returns true, and that unrelated IDs return false.
//
// The list of 9 IDs is the specification: this test encodes it explicitly so
// that any change requires an intentional, visible update here rather than a
// silent inline edit.  In particular, when an LLM refactors a switch with many
// nearly-identical cases it may "simplify" by collapsing ranges or dropping
// what looks like a duplicate.  Because each ID is a named subtest, such a
// regression surfaces immediately as a named test failure instead of a silent
// behaviour change.
func TestNeedsKernel612Guard(t *testing.T) {
	guardedIDs := []string{
		"ALAS2023-2025-935",
		"ALAS2023-2025-940",
		"ALAS2023-2025-948",
		"ALAS2023-2025-984",
		"ALAS2023-2025-994",
		"ALAS2023-2025-995",
		"ALAS2023-2025-1052",
		"ALAS2023-2025-1053",
		"ALAS2023-2025-1080",
	}
	for _, id := range guardedIDs {
		t.Run(id, func(t *testing.T) {
			if !amazon.NeedsKernel612Guard(id) {
				t.Errorf("NeedsKernel612Guard(%q) = false, want true", id)
			}
		})
	}

	notGuardedIDs := []string{
		"ALAS2023-2025-934",
		"ALAS2023-2025-1081",
		"ALAS2023-2025-1129",
		"ALAS2-2025-2738",
	}
	for _, id := range notGuardedIDs {
		t.Run(id, func(t *testing.T) {
			if amazon.NeedsKernel612Guard(id) {
				t.Errorf("NeedsKernel612Guard(%q) = true, want false", id)
			}
		})
	}
}

// TestIsKernel612SharedPackage tests isKernel612SharedPackage with every
// package name that appears in the 9 kernel6.12 advisories (ALAS2023-2025-935,
// -940, -948, -984, -994, -995, -1052, -1053, -1080). The package list is
// identical across all 9 advisories. Although this looks like an example-based
// test, the cases below are exhaustive: they cover all package names from those
// advisories.
// See applyKernel612Guard for the definition of "shared" packages.
func TestIsKernel612SharedPackage(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// Shared packages: kernel-* without "6.12" → true
		{"kernel-devel", true},
		{"kernel-headers", true},
		{"kernel-libbpf", true},
		{"kernel-libbpf-debuginfo", true},
		{"kernel-libbpf-devel", true},
		{"kernel-libbpf-static", true},
		{"kernel-modules-extra-common", true},
		{"kernel-tools", true},
		{"kernel-tools-debuginfo", true},
		{"kernel-tools-devel", true},

		// Shared packages: bpftool* without "6.12" → true
		{"bpftool", true},
		{"bpftool-debuginfo", true},

		// kernel-livepatch contains "6.12" → false (excluded by guard)
		{"kernel-livepatch-6.12.22-27.96", false},
		{"kernel-livepatch-6.12.35-55.103", false},

		// kernel6.12 packages: no "kernel-" or "bpftool" prefix → false
		{"kernel6.12", false},
		{"kernel6.12-debuginfo", false},
		{"kernel6.12-debuginfo-common-aarch64", false},
		{"kernel6.12-debuginfo-common-x86_64", false},
		{"kernel6.12-modules-extra", false},

		// perf/python3-perf packages: no matching prefix → false
		{"perf6.12", false},
		{"perf6.12-debuginfo", false},
		{"python3-perf6.12", false},
		{"python3-perf6.12-debuginfo", false},

		// Unrelated packages → false
		{"glibc", false},
		{"openssl", false},
		{"kernel", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := amazon.IsKernel612SharedPackage(tt.name); got != tt.want {
				t.Errorf("IsKernel612SharedPackage(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
