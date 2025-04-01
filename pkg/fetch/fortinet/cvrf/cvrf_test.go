package cvrf_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/cvrf"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		hasError bool
	}{
		{
			name: "happy path",
			args: []string{"FG-IR-13-008", "FG-IR-23-392"},
		},
		{
			name:     "404 not found",
			args:     []string{"FG-IR-12-001"},
			hasError: true,
		},
		{
			name:     "text/html",
			args:     []string{"FG-IR-24-259"},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "FG-IR-24-259":
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					if _, err := fmt.Fprintf(w, "%s", `<html>
<head></head>
<body>
<script type=\"text/javascript\">
eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--)d[e(c)]=k[c]||e(c);k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);return p}('1r Y=\"a+/=\";Q d(X){1r 13=\"\";1r y,z,A=\"\";1r I,J,K,L=\"\";1r U=0;X=X.15(/[^9-u-1w-8\\+\\/\\=]/S,\"\");E{I=Y.W(X.x(U++));J=Y.W(X.x(U++));K=Y.W(X.x(U++));L=Y.W(X.x(U++));y=(I<<2)|(J>>5);z=((J&1)<<5)|(K>>2);A=((K&4)<<6)|L;13=13+n.P(y);V(K!=7){13=13+n.P(z);}V(L!=7){13=13+n.P(A);}y=z=A=\"\";I=J=K=L=\"\";}1t(U<X.Z);17 1p(13);}1r 1c=\"D\";1r 1e= \"e=\";1r 1f= \"l=\";1r 1g= \"k=\";1r 1h= \"1s\";1r 1i= \"f=\";1r 1j= \"j=\";1r 1k= \"m=\";Q p(){1r 1v;V(1n s!=\\'1o\\'){1v=10 s();17 1v;}H V(1n b!=\\'1o\\'){1r v=[\"h.r\",\"h.r.4.0\",\"g.q\"];M(1r U=0;U<v.Z;U++){1m{1v=10 b(v[U]);}w(G){C;}17 1v;}}}Q t(G){V(1v.14==5){V(1v.1b==3){F.12();F.1u(1v.16);F.B();}}}1r 1v=p();V(1v){1v.11=t;1r 1q=\"N\";1q+=\"?\"+1c+\"=\"+d(1h);1v.12(\"i\",1q,1l);1v.1a(\"c-o\", \"1d/T\");1r 19=\"R=\"+\"O\";1v.18(19);}',62,95,'0|15|2|200|3|4|6|64|9|A|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789|ActiveXObject|Content|GFLTTQCMLIMVOBER|M0JERkQzMEFCOTZCMUVFODgxQkUyNDg3NzYyNzNCRTU|MEEzNDJFNTkxMjQwNkE0MTRBRTQ1RUYwQ0Y2NDlEMzM|Microsoft|Msxml2|POST|QUY0OTE1RDI1NTRFQTY2NUVEQ0U3MUFBODE1OTA2QjA|QkRGQUVFQkVENjQ3MjIwNzE5OUNBODU4M0JDRDlEMjg|RDY2NDM4MDhBRDRBRUNBQTM4QUJFQTY3RjA3RTg4REM|RjYyRjc3NkJCMTlDMDFEMkYwMDRGQjIxNEZFMjAzMkE|String|Type|UAIEADJCSXKVXQNH|XMLHTTP|XMLHttp|XMLHttpRequest|XYBTRDHFLTBDWFWU|Za|aVersions|catch|charAt|chr1|chr2|chr3|close|continue|cookiesession8341|do|document|e|else|enc1|enc2|enc3|enc4|for|/psirt/cvrf/FG-IR-24-259|R0VUIC9wc2lydC9jdnJmL0ZHLUlSLTE2LTAwOSBIVFRQLzEuMQ0KaG9zdDogd3d3LmZvcnRpZ3VhcmQuY29tDQpjb25uZWN0aW9uOiBrZWVwLWFsaXZlDQphY2NlcHQtZW5jb2Rpbmc6IGd6aXANCnVzZXItYWdlbnQ6IEdvLWh0dHAtY2xpZW50LzIuMA0KY29udGVudC1sZW5ndGg6IDANCg0K|fromCharCode|function|fwb_dat|g|html|i|if|indexOf|input|keyStr|length|new|onreadystatechange|open|output|readyState|replace|responseText|return|send|send_data|setRequestHeader|status|str1|text|tmevtre0|tmevtre1|tmevtre2|tmevtre3|tmevtre4|tmevtre5|tmevtre6|true|try|typeof|undefined|unescape|url|var|MUVBOUMzMzVEODA3Nzc0MzQ1QUU3QzAyRkUzRDRBOTI=|while|write|xhr|z0'.split('|'),0,{}))</script>
</body>
</html>
`); err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", fmt.Sprintf("%s.xml", strings.TrimPrefix(r.URL.Path, string(os.PathSeparator)))))
				}
			}))
			defer ts.Close() //nolint:errcheck

			dir := t.TempDir()
			err := cvrf.Fetch(tt.args, cvrf.WithDataURL(fmt.Sprintf("%s/%%s", ts.URL)), cvrf.WithDir(dir), cvrf.WithRetry(0), cvrf.WithConcurrency(1), cvrf.WithWait(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
				if err != nil {
					return err
				}

				got, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Fetch(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
