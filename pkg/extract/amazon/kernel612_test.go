package amazon_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/amazon"
)

// TestIsKernel612SharedPackage tests isKernel612SharedPackage with every
// package name that appears in the 9 kernel6.12 advisories (ALAS2023-2025-935,
// -940, -948, -984, -994, -995, -1052, -1053, -1080). The package list is
// identical across all 9 advisories.
//
// "Shared" means the package name is common to both the kernel 6.1 and
// kernel 6.12 branches in AL2023. For example, kernel-tools and bpftool are
// built from both branches but use the same unsuffixed name, whereas
// kernel6.12, perf6.12, etc. are unique to the 6.12 branch. The AND guard
// wraps these shared packages so that they match only when kernel6.12 is
// actually installed on the host, preventing false positives on kernel 6.1
// systems.
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
