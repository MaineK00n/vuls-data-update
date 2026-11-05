package cpecriterion_test

import (
	stderrors "errors"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"

	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
)

func TestPackCPEMatches(t *testing.T) {
	type args struct {
		criterion ccTypes.CPE
		matches   []ccTypes.CPE
	}
	tests := []struct {
		name       string
		args       args
		wantData   string
		wantUnpack []ccTypes.CPE
		wantErr    bool
	}{
		{
			name: "versions only",
			args: args{
				criterion: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
				matches: []ccTypes.CPE{
					"cpe:2.3:a:google:chrome:0.1.38.2:*:*:*:*:*:*:*",
					"cpe:2.3:a:google:chrome:0.1.38.1:*:*:*:*:*:*:*",
					"cpe:2.3:a:google:chrome:10.0.648.204:*:*:*:*:*:*:*",
				},
			},
			wantData: "00.1.38.1 72 010.0.648.204",
			wantUnpack: []ccTypes.CPE{
				"cpe:2.3:a:google:chrome:0.1.38.1:*:*:*:*:*:*:*",
				"cpe:2.3:a:google:chrome:0.1.38.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:google:chrome:10.0.648.204:*:*:*:*:*:*:*",
			},
		},
		{
			name: "update and later attributes, escaped characters, duplicates",
			args: args{
				criterion: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
				matches: []ccTypes.CPE{
					"cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*",
					"cpe:2.3:o:linux:linux_kernel:5.15:rc1:*:*:*:*:*:*",
					"cpe:2.3:o:linux:linux_kernel:5.15:-:*:*:*:*:*:*",
					"cpe:2.3:o:linux:linux_kernel:4.18.0\\-193.el8:*:*:*:*:*:*:*",
					"cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:android:*",
					"cpe:2.3:o:linux:linux_kernel:1.0\\::*:*:*:*:*:*:*",
					"cpe:2.3:o:linux:linux_kernel:1\\|0:*:*:*:*:*:*:*",
					"cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*",
				},
			},
			wantData: "01.0\\: 1\\|0 04.18.0\\-193.el8 05.15.10 7:*:*:*:*:*:android 4:- 5rc1",
			wantUnpack: []ccTypes.CPE{
				"cpe:2.3:o:linux:linux_kernel:1.0\\::*:*:*:*:*:*:*",
				"cpe:2.3:o:linux:linux_kernel:1\\|0:*:*:*:*:*:*:*",
				"cpe:2.3:o:linux:linux_kernel:4.18.0\\-193.el8:*:*:*:*:*:*:*",
				"cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:*:*",
				"cpe:2.3:o:linux:linux_kernel:5.15.10:*:*:*:*:*:android:*",
				"cpe:2.3:o:linux:linux_kernel:5.15:-:*:*:*:*:*:*",
				"cpe:2.3:o:linux:linux_kernel:5.15:rc1:*:*:*:*:*:*",
			},
		},
		{
			// A shared prefix longer than the 43 the length character can
			// express is cut there and the rest written out.
			name: "shared prefix beyond the length cap",
			args: args{
				criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				matches: []ccTypes.CPE{
					ccTypes.CPE("cpe:2.3:a:vendor:product:" + strings.Repeat("1.", 25) + "0:*:*:*:*:*:*:*"),
					ccTypes.CPE("cpe:2.3:a:vendor:product:" + strings.Repeat("1.", 25) + "1:*:*:*:*:*:*:*"),
				},
			},
			wantData: "0" + strings.Repeat("1.", 25) + "0 [" + strings.Repeat("1.", 25)[43:] + "1",
			wantUnpack: []ccTypes.CPE{
				ccTypes.CPE("cpe:2.3:a:vendor:product:" + strings.Repeat("1.", 25) + "0:*:*:*:*:*:*:*"),
				ccTypes.CPE("cpe:2.3:a:vendor:product:" + strings.Repeat("1.", 25) + "1:*:*:*:*:*:*:*"),
			},
		},
		{
			// The entries diverge right after a quoting backslash, so the
			// remainder starts with a bare quoted character; harmless, as
			// the separator never occurs in a name.
			name: "entries diverging inside an escape pair",
			args: args{
				criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				matches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:1.0:build\\|1:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:1.0:build\\-1:*:*:*:*:*:*",
				},
			},
			wantData: "01.0:build\\-1 :|1",
			wantUnpack: []ccTypes.CPE{
				"cpe:2.3:a:vendor:product:1.0:build\\-1:*:*:*:*:*:*",
				"cpe:2.3:a:vendor:product:1.0:build\\|1:*:*:*:*:*:*",
			},
		},
		{
			// The length cap lands right after a quoting backslash; the cut
			// stays there.
			name: "length cap falling inside an escape pair",
			args: args{
				criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				matches: []ccTypes.CPE{
					ccTypes.CPE("cpe:2.3:a:vendor:product:" + strings.Repeat("1.", 21) + "\\-1:*:*:*:*:*:*:*"),
					ccTypes.CPE("cpe:2.3:a:vendor:product:" + strings.Repeat("1.", 21) + "\\-2:*:*:*:*:*:*:*"),
				},
			},
			wantData: "0" + strings.Repeat("1.", 21) + "\\-1 [-2",
			wantUnpack: []ccTypes.CPE{
				ccTypes.CPE("cpe:2.3:a:vendor:product:" + strings.Repeat("1.", 21) + "\\-1:*:*:*:*:*:*:*"),
				ccTypes.CPE("cpe:2.3:a:vendor:product:" + strings.Repeat("1.", 21) + "\\-2:*:*:*:*:*:*:*"),
			},
		},
		{
			// A bare "|", which go-cpe accepts (it quotes punctuation on
			// unbind), is an ordinary byte of a name.
			name: "unquoted pipe",
			args: args{
				criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				matches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:1.0|1b:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				},
			},
			wantData: "01.0 3|1b",
			wantUnpack: []ccTypes.CPE{
				"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				"cpe:2.3:a:vendor:product:1.0|1b:*:*:*:*:*:*:*",
			},
		},
		{
			// The entries diverge inside a multi-byte character; the prefix
			// stops before it so the text stays valid UTF-8.
			name: "entries diverging inside a UTF-8 sequence",
			args: args{
				criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				matches: []ccTypes.CPE{
					"cpe:2.3:a:vendor:product:1.0:cafê:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:1.0:café:*:*:*:*:*:*",
				},
			},
			wantData: "01.0:café 7ê",
			wantUnpack: []ccTypes.CPE{
				"cpe:2.3:a:vendor:product:1.0:café:*:*:*:*:*:*",
				"cpe:2.3:a:vendor:product:1.0:cafê:*:*:*:*:*:*",
			},
		},
		{
			// A quoted backslash at the end of the last attribute is a
			// literal backslash, not an escape left open.
			name: "last attribute ending in a quoted backslash",
			args: args{
				criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				matches:   []ccTypes.CPE{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:x\\\\"},
			},
			wantData:   "01.0:*:*:*:*:*:*:x\\\\",
			wantUnpack: []ccTypes.CPE{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:x\\\\"},
		},
		{
			// The version is never dropped, so the reduced form is never
			// empty and an all-ANY name round-trips.
			name: "all attributes ANY",
			args: args{
				criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				matches:   []ccTypes.CPE{"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
			},
			wantData:   "0*",
			wantUnpack: []ccTypes.CPE{"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
		},
		{
			name:       "empty",
			args:       args{criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
			wantData:   "",
			wantUnpack: []ccTypes.CPE{},
		},
		{
			name: "entry with a different product -> error",
			args: args{
				criterion: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
				matches:   []ccTypes.CPE{"cpe:2.3:a:google:chrome_os:1.0:*:*:*:*:*:*:*"},
			},
			wantErr: true,
		},
		{
			name:    "malformed criterion -> error",
			args:    args{criterion: "cpe:2.3:a:google:chrome", matches: []ccTypes.CPE{"cpe:2.3:a:google:chrome:1.0:*:*:*:*:*:*:*"}},
			wantErr: true,
		},
		{
			// go-cpe reads the colon after "\\" as quoted and accepts the
			// name; split as the grammar has it, it has nine attributes.
			name: "entry with a colon after a quoted backslash -> error",
			args: args{
				criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				matches:   []ccTypes.CPE{"cpe:2.3:a:vendor:product:1\\\\:2:*:*:*:*:*:*:*"},
			},
			wantErr: true,
		},
		{
			name: "entry holding the separator -> error",
			args: args{
				criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				matches:   []ccTypes.CPE{"cpe:2.3:a:vendor:product:1 0:*:*:*:*:*:*:*"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ccTypes.PackCPEMatches(tt.args.criterion, tt.args.matches)
			if (err != nil) != tt.wantErr {
				t.Fatalf("PackCPEMatches() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if p.Encoding != ccTypes.PackedEncodingFC {
				t.Errorf("Encoding = %q, want %q", p.Encoding, ccTypes.PackedEncodingFC)
			}
			if p.Data != tt.wantData {
				t.Errorf("Data = %q, want %q", p.Data, tt.wantData)
			}
			if !utf8.ValidString(p.Data) {
				t.Errorf("Data = %q is not valid UTF-8", p.Data)
			}
			got, err := p.Unpack(tt.args.criterion)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantUnpack, got); diff != "" {
				t.Errorf("(-expected +got):\n%s", diff)
			}
		})
	}
}

func TestCPEMatchesPacked_Unpack_errors(t *testing.T) {
	tests := []struct {
		name            string
		p               *ccTypes.CPEMatchesPacked
		wantUnsupported bool
	}{
		{name: "unknown encoding", p: &ccTypes.CPEMatchesPacked{Encoding: "fc+zstd", Data: "010.0.0"}, wantUnsupported: true},
		{name: "data without an encoding", p: &ccTypes.CPEMatchesPacked{Data: "010.0.0"}},
		{name: "empty entry", p: &ccTypes.CPEMatchesPacked{Encoding: ccTypes.PackedEncodingFC, Data: "010.0.0  51"}},
		{name: "empty reduced entry", p: &ccTypes.CPEMatchesPacked{Encoding: ccTypes.PackedEncodingFC, Data: "0"}},
		{name: "more than eight attributes", p: &ccTypes.CPEMatchesPacked{Encoding: ccTypes.PackedEncodingFC, Data: "01:2:3:4:5:6:7:8:9"}},
		{name: "entry ending in an unquoted backslash", p: &ccTypes.CPEMatchesPacked{Encoding: ccTypes.PackedEncodingFC, Data: "01:2:3:4:5:6:7:8\\"}},
		{name: "length character below the range", p: &ccTypes.CPEMatchesPacked{Encoding: ccTypes.PackedEncodingFC, Data: "010.0.0 *1"}},
		{name: "length character above the range", p: &ccTypes.CPEMatchesPacked{Encoding: ccTypes.PackedEncodingFC, Data: "010.0.0 \\1"}},
		{name: "prefix longer than previous", p: &ccTypes.CPEMatchesPacked{Encoding: ccTypes.PackedEncodingFC, Data: "010.0.0 91"}},
		{name: "prefix ending inside a UTF-8 sequence", p: &ccTypes.CPEMatchesPacked{Encoding: ccTypes.PackedEncodingFC, Data: "01.0:café 8\xaa"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.p.Unpack("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")
			if err == nil {
				t.Fatal("expected error has not occurred")
			}
			// Only an encoding outside the vocabulary is reported as
			// unsupported; malformed data under a known or empty one is not.
			if _, ok := stderrors.AsType[*ccTypes.UnsupportedPackedEncodingError](err); ok != tt.wantUnsupported {
				t.Errorf("UnsupportedPackedEncodingError = %v, want %v (err: %v)", ok, tt.wantUnsupported, err)
			}
		})
	}
	for name, p := range map[string]*ccTypes.CPEMatchesPacked{"nil": nil, "zero value": {}} {
		t.Run(name, func(t *testing.T) {
			got, err := p.Unpack("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")
			if err != nil || got != nil {
				t.Errorf("Unpack() = %v, %v; want nil, nil", got, err)
			}
		})
	}
}

func TestPackable(t *testing.T) {
	tests := []struct {
		name      string
		criterion ccTypes.CPE
		m         ccTypes.CPE
		want      bool
	}{
		{name: "same product", criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", m: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", want: true},
		{name: "criterion with a wildcard product", criterion: "cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*", m: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", want: false},
		{name: "different product", criterion: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", m: "cpe:2.3:a:google:chrome_os:1.0:*:*:*:*:*:*:*", want: false},
		{name: "malformed criterion", criterion: "cpe:2.3:a:google:chrome", m: "cpe:2.3:a:google:chrome:1.0:*:*:*:*:*:*:*", want: false},
		{name: "unquoted pipe", criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", m: "cpe:2.3:a:vendor:product:1|b:*:*:*:*:*:*:*", want: true},
		{name: "non-ASCII", criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", m: "cpe:2.3:a:vendor:product:1.0:café:*:*:*:*:*:*", want: true},
		{name: "all attributes ANY", criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", m: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", want: true},
		{name: "quoted colon", criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", m: "cpe:2.3:a:vendor:product:1\\:2:*:*:*:*:*:*:*", want: true},
		{name: "colon after a quoted backslash", criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", m: "cpe:2.3:a:vendor:product:1\\\\:2:*:*:*:*:*:*:*", want: false},
		{name: "too few attributes", criterion: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", m: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ccTypes.Packable(tt.criterion, tt.m); got != tt.want {
				t.Errorf("Packable() = %v, want %v", got, tt.want)
			}
			// Packable is the gate and PackCPEMatches the backstop: they
			// must agree on every name.
			if _, err := ccTypes.PackCPEMatches(tt.criterion, []ccTypes.CPE{tt.m}); (err == nil) != tt.want {
				t.Errorf("PackCPEMatches() error = %v, want %v", err, !tt.want)
			}
		})
	}
}

func TestPackedEncoding_Compare(t *testing.T) {
	got := []ccTypes.PackedEncoding{"zzz", "aaa", ccTypes.PackedEncodingFC}
	slices.SortFunc(got, ccTypes.PackedEncoding.Compare)
	want := []ccTypes.PackedEncoding{ccTypes.PackedEncodingFC, "aaa", "zzz"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-expected +got):\n%s", diff)
	}
}
