package alpine

// secdb represents a type included in files from the Alpine repository
type secdb struct {
	Apkurl        string   `json:"apkurl"`
	Archs         []string `json:"archs"`
	Reponame      string   `json:"reponame"`
	Urlprefix     string   `json:"urlprefix"`
	Distroversion string   `json:"distroversion"`
	Packages      []struct {
		Pkg Package `json:"pkg"`
	} `json:"packages"`
}

type Advisory struct {
	Apkurl        string    `json:"apkurl"`
	Archs         []string  `json:"archs"`
	Reponame      string    `json:"reponame"`
	Urlprefix     string    `json:"urlprefix"`
	Distroversion string    `json:"distroversion"`
	Packages      []Package `json:"packages"`
}

type Package struct {
	Name     string              `json:"name"`
	Secfixes map[string][]string `json:"secfixes"`
}
