package secdb

type Advisory struct {
	Apkurl    string   `json:"apkurl"`
	Archs     []string `json:"archs"`
	Reponame  string   `json:"reponame"`
	Urlprefix string   `json:"urlprefix"`
	Packages  []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}
