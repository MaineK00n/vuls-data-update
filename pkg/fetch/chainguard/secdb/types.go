package secdb

type Advisory struct {
	Apkurl    string    `json:"apkurl"`
	Archs     []string  `json:"archs"`
	Reponame  string    `json:"reponame"`
	Urlprefix string    `json:"urlprefix"`
	Packages  []Package `json:"packages"`
}

type Package struct {
	Pkg struct {
		Name     string              `json:"name"`
		Secfixes map[string][]string `json:"secfixes"`
	} `json:"pkg"`
}
