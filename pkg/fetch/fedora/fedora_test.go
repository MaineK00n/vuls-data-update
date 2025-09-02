package fedora_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fedora"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata fedora.DataURL
		hasError bool
	}{
		{
			name: "happy",
			testdata: fedora.DataURL{
				Release:  "testdata/fixtures/releases?page=%d&rows_per_page=%d",
				Advisory: "testdata/fixtures/updates/?releases=%s&type=security&page=%d&rows_per_page=%d",
				Package:  "testdata/fixtures/kojihub",
				Bugzilla: "testdata/fixtures/bugzilla/show_bug.cgi?ctype=xml&id=%s",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasPrefix(r.URL.Path, "/testdata/fixtures/releases"):
					type releasePage struct {
						Releases    []any `json:"releases"`
						Page        int   `json:"page"`
						Pages       int   `json:"pages"`
						RowsPerPage int   `json:"rows_per_page"`
						Total       int   `json:"total"`
					}

					f, err := os.Open("testdata/fixtures/releases/releases.json")
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					defer f.Close()

					var p releasePage
					if err := json.NewDecoder(f).Decode(&p); err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					page, err := strconv.Atoi(r.URL.Query().Get("page"))
					if err != nil || page < 1 {
						http.Error(w, "Bad Request", http.StatusBadRequest)
						return
					}
					rows, err := strconv.Atoi(r.URL.Query().Get("rows_per_page"))
					if err != nil || rows < 0 {
						http.Error(w, "Bad Request", http.StatusBadRequest)
						return
					}
					pages := p.Total / rows
					if p.Total%rows != 0 {
						pages++
					}
					p.Page = page
					p.RowsPerPage = rows
					p.Pages = pages

					start := (page - 1) * rows
					end := start + rows
					if start > len(p.Releases) {
						start, end = 0, 0
					} else if end > len(p.Releases) {
						end = len(p.Releases)
					}
					p.Releases = p.Releases[start:end]

					bs, err := json.Marshal(p)
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					http.ServeContent(w, r, fmt.Sprintf("index.html?page=%d&rows_per_page=%d", page, rows), time.Now(), bytes.NewReader(bs))
				case strings.HasPrefix(r.URL.Path, "/testdata/fixtures/updates"):
					type advisoryPage struct {
						Updates        []any `json:"updates"`
						Page           int   `json:"page"`
						Pages          int   `json:"pages"`
						RowsPerPage    int   `json:"rows_per_page"`
						Total          int   `json:"total"`
						Chrome         bool  `json:"chrome"`
						DisplayUser    bool  `json:"display_user"`
						DisplayRequest bool  `json:"display_request"`
						Package        any   `json:"package"`
					}

					release := r.URL.Query().Get("releases")
					f, err := os.Open(fmt.Sprintf("testdata/fixtures/updates/%s.json", release))
					if err != nil {
						if os.IsNotExist(err) {
							http.Error(w, "Bad Request", http.StatusBadRequest)
							return
						}
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					defer f.Close()

					var us []any
					if err := json.NewDecoder(f).Decode(&us); err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					page, err := strconv.Atoi(r.URL.Query().Get("page"))
					if err != nil || page < 1 {
						http.Error(w, "Bad Request", http.StatusBadRequest)
						return
					}
					rows, err := strconv.Atoi(r.URL.Query().Get("rows_per_page"))
					if err != nil || rows < 0 {
						http.Error(w, "Bad Request", http.StatusBadRequest)
						return
					}

					p := advisoryPage{
						Updates:     us,
						Page:        page,
						RowsPerPage: rows,
						Total:       len(us),
					}
					pages := p.Total / rows
					if p.Total%rows != 0 {
						pages++
					}
					p.Pages = pages

					start := (page - 1) * rows
					end := start + rows
					if start > len(p.Updates) {
						start, end = 0, 0
					} else if end > len(p.Updates) {
						end = len(p.Updates)
					}
					p.Updates = p.Updates[start:end]

					buf := new(bytes.Buffer)
					e := json.NewEncoder(buf)
					e.SetEscapeHTML(false)
					if err := e.Encode(p); err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					http.ServeContent(w, r, fmt.Sprintf("index.html?releases=%s&type=security&page=%d&rows_per_page=%d", release, page, rows), time.Now(), bytes.NewReader(buf.Bytes()))
				case strings.HasPrefix(r.URL.Path, "/testdata/fixtures/kojihub"):
					bs, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					type methodCall struct {
						MethodName string `xml:"methodName"`
					}
					var c methodCall
					if err := xml.Unmarshal(bs, &c); err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					switch c.MethodName {
					case "findBuildID":
						type methodCall struct {
							Params struct {
								Param struct {
									Value struct {
										String string `xml:"string"`
									} `xml:"value"`
								} `xml:"param"`
							} `xml:"params"`
						}
						var c methodCall
						if err := xml.Unmarshal(bs, &c); err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						http.ServeFile(w, r, fmt.Sprintf("testdata/fixtures/kojihub/findBuildID/%s.xml", c.Params.Param.Value.String))
					case "getBuild":
						type methodCall struct {
							Params struct {
								Param struct {
									Value struct {
										String string `xml:"string"`
									} `xml:"value"`
								} `xml:"param"`
							} `xml:"params"`
						}
						var c methodCall
						if err := xml.Unmarshal(bs, &c); err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						http.ServeFile(w, r, fmt.Sprintf("testdata/fixtures/kojihub/getBuild/%s.xml", c.Params.Param.Value.String))
					case "listArchives":
						type methodCall struct {
							Params struct {
								Param struct {
									Value struct {
										Int int `xml:"int"`
									} `xml:"value"`
								} `xml:"param"`
							} `xml:"params"`
						}
						var c methodCall
						if err := xml.Unmarshal(bs, &c); err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						http.ServeFile(w, r, fmt.Sprintf("testdata/fixtures/kojihub/listArchives/%d.xml", c.Params.Param.Value.Int))
					case "listRPMs":
						type methodCall struct {
							Params struct {
								Param []struct {
									Value struct {
										Int *int `xml:"int"`
									} `xml:"value"`
								} `xml:"param"`
							} `xml:"params"`
						}
						var c methodCall
						if err := xml.Unmarshal(bs, &c); err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}

						var buildID, imageID *int
						for i, p := range c.Params.Param {
							switch i {
							case 0:
								buildID = p.Value.Int
							case 2:
								imageID = p.Value.Int
							default:
							}
						}
						id := buildID
						if imageID != nil {
							id = imageID
						}
						if id == nil {
							http.Error(w, "Bad Request", http.StatusBadRequest)
							return
						}

						http.ServeFile(w, r, fmt.Sprintf("testdata/fixtures/kojihub/listRPMs/%d.xml", *id))
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
						return
					}
				case strings.HasPrefix(r.URL.Path, "/testdata/fixtures/bugzilla"):
					http.ServeFile(w, r, fmt.Sprintf("testdata/fixtures/bugzilla/%s.xml", r.URL.Query().Get("id")))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := fedora.Fetch([]string{"__current__", "__pending__", "__archived__"},
				fedora.WithDataURL(fedora.DataURL{
					Release:  fmt.Sprintf("%s/%s", ts.URL, tt.testdata.Release),
					Advisory: fmt.Sprintf("%s/%s", ts.URL, tt.testdata.Advisory),
					Package:  fmt.Sprintf("%s/%s", ts.URL, tt.testdata.Package),
					Bugzilla: fmt.Sprintf("%s/%s", ts.URL, tt.testdata.Bugzilla),
				}), fedora.WithDir(dir), fedora.WithRetry(0), fedora.WithConcurrency(1), fedora.WithWait(0), fedora.WithRowsPerPage(2))
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
				dir, y := filepath.Split(filepath.Clean(dir))
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), y, file))
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
