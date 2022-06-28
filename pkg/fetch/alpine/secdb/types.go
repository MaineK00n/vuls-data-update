package secdb

// Advisory represents a type included in files from the Alpine repository
type Advisory struct {
	Apkurl        string   `json:"apkurl"`
	Archs         []string `json:"archs"`
	Reponame      string   `json:"reponame"`
	Urlprefix     string   `json:"urlprefix"`
	Distroversion string   `json:"distroversion"`
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}
