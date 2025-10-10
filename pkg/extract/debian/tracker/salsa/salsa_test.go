package salsa_test

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/debian/tracker/salsa"
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
			args: "./testdata/fixtures/happy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := salsa.Extract(tt.args, salsa.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
			if err != nil {
				t.Error("unexpected error:", err)
			}
			gp, err := filepath.Abs(dir)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			utiltest.Diff(t, ep, gp)
		})
	}
}

func Test_maxPackageStatus(t *testing.T) {
	type args struct {
		cves []salsa.PackageAnnotation
		advs map[string][]salsa.PackageAnnotation
	}
	tests := []struct {
		name string
		args args
		want salsa.PackageAnnotation
	}{
		{
			// CVE fixed (release-specific) version > Advisory fixed version
			// e.g. CVE-2023-20588 bullseye linux: CVE:5.10.197-1 > DSA-5480-1:5.10.191-1
			// salsa-api agrees with CVE (higher version)
			name: "fixed version: CVE > ADV, select higher version (CVE)",
			args: args{
				cves: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bullseye", Version: "5.10.197-1"},
				},
				advs: map[string][]salsa.PackageAnnotation{
					"DSA-5480-1": {{Kind: "fixed", Release: "bullseye", Version: "5.10.191-1"}},
				},
			},
			want: salsa.PackageAnnotation{Kind: "fixed", Release: "bullseye", Version: "5.10.197-1"},
		},
		{
			// Advisory fixed version > CVE fixed (release-specific) version
			// e.g. CVE-2022-1184 bullseye linux: CVE:5.10.140-1 < DSA-5257-1:5.10.149-1
			// salsa-api agrees with ADV (higher version)
			name: "fixed version: CVE < ADV, select higher version (ADV)",
			args: args{
				cves: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bullseye", Version: "5.10.140-1"},
				},
				advs: map[string][]salsa.PackageAnnotation{
					"DSA-5257-1": {{Kind: "fixed", Release: "bullseye", Version: "5.10.149-1"}},
				},
			},
			want: salsa.PackageAnnotation{Kind: "fixed", Release: "bullseye", Version: "5.10.149-1"},
		},
		{
			// CVE has unfixed-type (no-dsa) but Advisory has fixed
			// Advisory fixed should win because fixed > no-dsa in kind priority
			name: "kind priority: ADV fixed > CVE no-dsa",
			args: args{
				cves: []salsa.PackageAnnotation{
					{Kind: "no-dsa", Release: "bullseye", Description: "Minor issue"},
				},
				advs: map[string][]salsa.PackageAnnotation{
					"DSA-5000-1": {{Kind: "fixed", Release: "bullseye", Version: "1.0.0-1"}},
				},
			},
			want: salsa.PackageAnnotation{Kind: "fixed", Release: "bullseye", Version: "1.0.0-1"},
		},
		{
			// CVE has unfixed-type (ignored) but Advisory has fixed
			name: "kind priority: ADV fixed > CVE ignored",
			args: args{
				cves: []salsa.PackageAnnotation{
					{Kind: "ignored", Release: "bookworm", Description: "unimportant"},
				},
				advs: map[string][]salsa.PackageAnnotation{
					"DLA-3000-1": {{Kind: "fixed", Release: "bookworm", Version: "2.0.0-1"}},
				},
			},
			want: salsa.PackageAnnotation{Kind: "fixed", Release: "bookworm", Version: "2.0.0-1"},
		},
		{
			// Release-less fixed (unstable/sid) vs release-specific unfixed
			// release-specific (has release) should be preferred over release-less
			name: "release-less fixed vs release-specific no-dsa",
			args: args{
				cves: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "", Version: "3.0.0-1"},
					{Kind: "no-dsa", Release: "bookworm", Description: "Minor issue"},
				},
				advs: map[string][]salsa.PackageAnnotation{},
			},
			want: salsa.PackageAnnotation{Kind: "no-dsa", Release: "bookworm", Description: "Minor issue"},
		},
		{
			// Multiple advisories for same release, select highest fixed version
			// e.g. CVE-2023-20588 had xref to DSA-5492-1 and DSA-5480-1
			name: "multiple advisories: select highest fixed version",
			args: args{
				cves: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bullseye", Version: "5.10.197-1"},
				},
				advs: map[string][]salsa.PackageAnnotation{
					"DSA-5480-1": {{Kind: "fixed", Release: "bullseye", Version: "5.10.191-1"}},
					"DSA-5492-1": {{Kind: "fixed", Release: "bullseye", Version: "5.10.195-1"}},
				},
			},
			want: salsa.PackageAnnotation{Kind: "fixed", Release: "bullseye", Version: "5.10.197-1"},
		},
		{
			// CVE fixed only (no advisory)
			name: "CVE fixed only, no advisory",
			args: args{
				cves: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bookworm", Version: "1.2.3-1"},
				},
				advs: map[string][]salsa.PackageAnnotation{},
			},
			want: salsa.PackageAnnotation{Kind: "fixed", Release: "bookworm", Version: "1.2.3-1"},
		},
		{
			// unfixed kind only
			name: "unfixed only",
			args: args{
				cves: []salsa.PackageAnnotation{
					{Kind: "unfixed", Release: "bookworm"},
				},
				advs: map[string][]salsa.PackageAnnotation{},
			},
			want: salsa.PackageAnnotation{Kind: "unfixed", Release: "bookworm"},
		},
		{
			// end-of-life in CVE, fixed in advisory
			// e.g. CVE-2011-2800 squeeze chromium-browser: CVE:end-of-life + DSA-2307-1:fixed(6.0.472.63~r59945-5+squeeze6)
			name: "kind priority: ADV fixed > CVE end-of-life",
			args: args{
				cves: []salsa.PackageAnnotation{
					{Kind: "end-of-life", Release: "squeeze"},
				},
				advs: map[string][]salsa.PackageAnnotation{
					"DSA-2307-1": {{Kind: "fixed", Release: "squeeze", Version: "6.0.472.63~r59945-5+squeeze6"}},
				},
			},
			want: salsa.PackageAnnotation{Kind: "fixed", Release: "squeeze", Version: "6.0.472.63~r59945-5+squeeze6"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := salsa.MaxPackageStatus(tt.args.cves, tt.args.advs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("maxPackageStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_maxSeverity(t *testing.T) {
	type args struct {
		anns []salsa.PackageAnnotation
	}
	tests := []struct {
		name    string
		args    args
		want    *string
		wantErr bool
	}{
		{
			name: "no annotations",
			args: args{
				anns: []salsa.PackageAnnotation{},
			},
			want: nil,
		},
		{
			name: "no flags",
			args: args{
				anns: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bookworm", Version: "1.0.0-1"},
				},
			},
			want: nil,
		},
		{
			name: "single annotation with single severity",
			args: args{
				anns: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bookworm", Version: "1.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("low")}}},
				},
			},
			want: new("low"),
		},
		{
			name: "single annotation with bug flag only (no severity)",
			args: args{
				anns: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bookworm", Version: "1.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Bug: new(123456)}}},
				},
			},
			want: nil,
		},
		{
			name: "single annotation with severity and bug",
			args: args{
				anns: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bookworm", Version: "1.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("medium")}, {Bug: new(123456)}}},
				},
			},
			want: new("medium"),
		},
		{
			name: "release-specific severity preferred over release-less",
			args: args{
				anns: []salsa.PackageAnnotation{
					{Kind: "fixed", Version: "2.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("high")}}},
					{Kind: "fixed", Release: "bookworm", Version: "1.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("low")}}},
				},
			},
			want: new("low"),
		},
		{
			name: "release-less severity when only release-less exists",
			args: args{
				anns: []salsa.PackageAnnotation{
					{Kind: "fixed", Version: "2.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("high")}}},
					{Kind: "no-dsa", Release: "bookworm"},
				},
			},
			want: new("high"),
		},
		{
			name: "unexpected severity value",
			args: args{
				anns: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bookworm", Version: "1.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("critical")}}},
				},
			},
			wantErr: true,
		},
		{
			name: "multiple severities in single annotation",
			args: args{
				anns: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bookworm", Version: "1.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("low")}, {Severity: new("high")}}},
				},
			},
			wantErr: true,
		},
		{
			name: "more than two annotations with severity",
			args: args{
				anns: []salsa.PackageAnnotation{
					{Kind: "fixed", Release: "bookworm", Version: "1.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("low")}}},
					{Kind: "fixed", Release: "bullseye", Version: "1.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("medium")}}},
					{Kind: "fixed", Version: "2.0.0-1", Flags: []struct {
						Bug      *int    `json:"bug,omitempty"`
						Severity *string `json:"severity,omitempty"`
					}{{Severity: new("high")}}},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := salsa.MaxSeverity(tt.args.anns)
			if (err != nil) != tt.wantErr {
				t.Errorf("maxSeverity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("maxSeverity() = %v, want %v", got, tt.want)
			}
		})
	}
}
