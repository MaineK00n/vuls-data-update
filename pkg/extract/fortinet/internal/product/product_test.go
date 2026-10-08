package product_test

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/product"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

func TestBakeVersion(t *testing.T) {
	type args struct {
		cpe     string
		version string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "concrete version",
			args: args{cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", version: "7.4.3"},
			want: "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*",
		},
		{
			name: "hyphenated version",
			args: args{cpe: "cpe:2.3:o:fortinet:fortiswitch:*:*:*:*:*:*:*:*", version: "6.1-2-29"},
			want: "cpe:2.3:o:fortinet:fortiswitch:6.1-2-29:*:*:*:*:*:*:*",
		},
		{
			name:    "invalid cpe",
			args:    args{cpe: "not-a-cpe", version: "1.0.0"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := product.BakeVersion(tt.args.cpe, tt.args.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("BakeVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("BakeVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// IsExactVersion honors per-product version arity: the same "X.Y" token is a
// concrete release for a two-component product (IPS Engine "7.166") but a
// train for a three-component one (FortiOS "7.4"). FortiSandbox Cloud/PaaS
// stay on the three-component rule: their two-component tokens ("23.4",
// "5.0") sit above real build-suffixed releases ("23.4.4350", "5.0.4") in the
// corpus, i.e. they are trains.
func TestIsExactVersion(t *testing.T) {
	type args struct {
		name string
		ver  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// Three-component products: >= 3 components is exact, "X.Y" / "X" are trains.
		{name: "three-component product: three components is exact", args: args{name: "FortiOS", ver: "7.4.3"}, want: true},
		{name: "three-component product: four components is exact", args: args{name: "FortiOS", ver: "7.4.3.1"}, want: true},
		{name: "three-component product: letter component is exact", args: args{name: "FortiSASE", ver: "25.2.a"}, want: true},
		{name: "three-component product: four components with letter is exact", args: args{name: "FortiSASE", ver: "25.1.a.2"}, want: true},
		{name: "three-component product: two components is a train", args: args{name: "FortiOS", ver: "7.4"}, want: false},
		{name: "three-component product: bare major is a train", args: args{name: "FortiOS", ver: "24"}, want: false},
		{name: "three-component product: empty version is not exact", args: args{name: "FortiOS", ver: ""}, want: false},
		{name: "FortiSandbox stays on the three-component rule", args: args{name: "FortiSandbox", ver: "5.0"}, want: false},
		// Two-component products: "X.Y" is exact, a bare major is a train.
		{name: "two-component product: two components is exact", args: args{name: "FortiAuthenticator OutlookAgent", ver: "2.1"}, want: true},
		{name: "two-component product: large minor is exact", args: args{name: "IPS Engine", ver: "7.166"}, want: true},
		{name: "two-component product: bare major is a train", args: args{name: "IPS Engine", ver: "7"}, want: false},
		{name: "two-component product: AV Engine two components is exact", args: args{name: "AV Engine", ver: "6.137"}, want: true},
		{name: "two-component product: legacy three components is still exact", args: args{name: "AV Engine", ver: "4.4.54"}, want: true},
		{name: "two-component product: empty version is not exact", args: args{name: "AV Engine", ver: ""}, want: false},
		// FortiSandbox Cloud/PaaS mix year-based and build-suffixed schemes;
		// their two-component tokens are trains (23.4 < 23.4.4350 exists).
		{name: "FortiSandbox Cloud: year-based two components is a train", args: args{name: "FortiSandbox Cloud", ver: "23.4"}, want: false},
		{name: "FortiSandbox Cloud: three components is exact", args: args{name: "FortiSandbox Cloud", ver: "5.0.4"}, want: true},
		{name: "FortiSandbox PaaS: year-based two components is a train", args: args{name: "FortiSandbox PaaS", ver: "23.4"}, want: false},
		{name: "FortiSandbox PaaS: build-suffixed release is exact", args: args{name: "FortiSandbox PaaS", ver: "23.4.4350"}, want: true},
		// Unknown product falls back to the three-component rule.
		{name: "unknown product: two components is a train", args: args{name: "FortiNonexistent", ver: "1.2"}, want: false},
		{name: "unknown product: three components is exact", args: args{name: "FortiNonexistent", ver: "1.2.3"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := product.IsExactVersion(tt.args.name, tt.args.ver); got != tt.want {
				t.Errorf("IsExactVersion(%q, %q) = %v, want %v", tt.args.name, tt.args.ver, got, tt.want)
			}
		})
	}
}

func TestTrainRange(t *testing.T) {
	type args struct {
		name  string
		train string
	}
	tests := []struct {
		name    string
		args    args
		want    ccRangeTypes.Range
		wantErr bool
	}{
		{name: "two-component train", args: args{name: "FortiOS", train: "7.0"}, want: ccRangeTypes.Range{GreaterEqual: "7.0", LessThan: "7.1"}},
		{name: "bare major train", args: args{name: "FortiOS", train: "7"}, want: ccRangeTypes.Range{GreaterEqual: "7", LessThan: "8"}},
		{name: "year-based bare major train", args: args{name: "FortiSandbox Cloud", train: "24"}, want: ccRangeTypes.Range{GreaterEqual: "24", LessThan: "25"}},
		// Unknown product falls back to the three-component rule; also
		// exercises the multi-digit last-component increment.
		{name: "unknown product multi-digit last component", args: args{name: "FortiNonexistent", train: "6.253"}, want: ccRangeTypes.Range{GreaterEqual: "6.253", LessThan: "6.254"}},
		{name: "non-numeric token", args: args{name: "FortiOS", train: "abc"}, wantErr: true},
		{name: "concrete three-component version is not a train", args: args{name: "FortiOS", train: "7.0.0"}, wantErr: true},
		{name: "concrete four-component version is not a train", args: args{name: "FortiOS", train: "7.4.3.1"}, wantErr: true},
		// For a twoComponentVersions product even "X.Y" is a concrete release,
		// not a train; a bare major still ranges.
		{name: "two-component product: two components is not a train", args: args{name: "IPS Engine", train: "7.166"}, wantErr: true},
		{name: "two-component product: bare major train", args: args{name: "IPS Engine", train: "7"}, want: ccRangeTypes.Range{GreaterEqual: "7", LessThan: "8"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := product.TrainRange(tt.args.name, tt.args.train)
			if (err != nil) != tt.wantErr {
				t.Fatalf("TrainRange(%q, %q) error = %v, wantErr %v", tt.args.name, tt.args.train, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("TrainRange(%q, %q) (-want +got):\n%s", tt.args.name, tt.args.train, diff)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name      string
		wantCPEs  []string
		wantRange ccRangeTypes.RangeType
		wantOK    bool
	}{
		// Fortinet's CNA CPE and NVD's agree.
		{name: "FortiOS", wantCPEs: []string{"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"}, wantRange: ccRangeTypes.RangeTypeFortinetFortiOS, wantOK: true},
		{name: "FortiSASE", wantCPEs: []string{"cpe:2.3:a:fortinet:fortisase:*:*:*:*:*:*:*:*"}, wantRange: ccRangeTypes.RangeTypeFortinetFortiSASE, wantOK: true},
		// The CNA CPE first, then the CPE published before it.
		{name: "  FortiProxy  ", wantCPEs: []string{"cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortiproxy:*:*:*:*:*:*:*:*"}, wantRange: ccRangeTypes.RangeTypeFortinetFortiProxy, wantOK: true},
		// A platform variant takes NVD's product with NVD's target_sw, Mac
		// both the current and the older one.
		{name: "FortiClientWindows", wantCPEs: []string{"cpe:2.3:a:fortinet:forticlientwindows:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:windows:*:*"}, wantRange: ccRangeTypes.RangeTypeFortinetFortiClient, wantOK: true},
		{name: "FortiClientMac", wantCPEs: []string{"cpe:2.3:a:fortinet:forticlientmac:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:macos:*:*", "cpe:2.3:a:fortinet:forticlient:*:*:*:*:*:mac_os_x:*:*"}, wantRange: ccRangeTypes.RangeTypeFortinetFortiClient, wantOK: true},
		// Fortinet's records name FortiSOAR apart from its PaaS and on-premise
		// deployments, which NVD folds into FortiSOAR.
		{name: "FortiSOAR", wantCPEs: []string{"cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*"}, wantRange: ccRangeTypes.RangeTypeFortinetFortiSOAR, wantOK: true},
		{name: "FortiSOAR PaaS", wantCPEs: []string{"cpe:2.3:a:fortinet:fortisoarpaas:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortisoar:*:*:*:*:*:*:*:*"}, wantRange: ccRangeTypes.RangeTypeFortinetFortiSOAR, wantOK: true},
		// The agent takes NVD's product for it, not FortiAuthenticator's.
		{name: "FortiAuthenticator OutlookAgent", wantCPEs: []string{"cpe:2.3:a:fortinet:fortiauthenticatoroutlookagent:*:*:*:*:*:*:*:*", "cpe:2.3:a:fortinet:fortiauthenticator_agent_for_microsoft_outlook_web_access:*:*:*:*:*:*:*:*"}, wantRange: ccRangeTypes.RangeTypeFortinetFortiAuthenticator, wantOK: true},
		// No Fortinet CVE record gives FortiSIEM Cloud a CPE yet, nor does NVD:
		// the CNA's naming rule, and "a" for a service.
		{name: "FortiSIEM Cloud", wantCPEs: []string{"cpe:2.3:a:fortinet:fortisiemcloud:*:*:*:*:*:*:*:*"}, wantRange: ccRangeTypes.RangeTypeFortinetFortiSIEMCloud, wantOK: true},
		{name: "Nonexistent Product", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes, rt, ok := product.Resolve(tt.name)
			if ok != tt.wantOK || rt != tt.wantRange {
				t.Errorf("Resolve(%q) = (_, %v, %v), want (_, %v, %v)", tt.name, rt, ok, tt.wantRange, tt.wantOK)
			}
			if diff := cmp.Diff(tt.wantCPEs, cpes); diff != "" {
				t.Errorf("Resolve(%q) cpes (-want +got):\n%s", tt.name, diff)
			}
		})
	}
}

// Every product has a CNA CPE, and its CPEs are well-formed, Fortinet's,
// version-wildcarded and unrepeated.
func TestTableCPEs(t *testing.T) {
	for _, name := range product.Names() {
		cna, nvd := product.CPEs(name)
		if len(cna) == 0 {
			t.Errorf("%q: no CNA CPE", name)
		}
		seen := make(map[string]bool, len(cna)+len(nvd))
		for _, cpe := range slices.Concat(cna, nvd) {
			if seen[cpe] {
				t.Errorf("%q: CPE %q repeated", name, cpe)
			}
			seen[cpe] = true
			wfn, err := naming.UnbindFS(cpe)
			if err != nil {
				t.Errorf("%q: unbind %q: %v", name, cpe, err)
				continue
			}
			if v, ok := wfn.Get(common.AttributeVendor).(string); !ok || v != "fortinet" {
				t.Errorf("%q: CPE %q vendor is not fortinet", name, cpe)
			}
			// ANY, not just any logical value: NA ("-") would claim the
			// product has no version.
			if v, ok := wfn.Get(common.AttributeVersion).(common.LogicalValue); !ok || !v.IsANY() {
				t.Errorf("%q: CPE %q version is not ANY", name, cpe)
			}
		}
	}
}
