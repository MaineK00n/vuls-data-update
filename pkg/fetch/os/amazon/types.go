package amazon

import "time"

type releasemd struct {
	Releases struct {
		Release []struct {
			Version string `xml:"version,attr"`
			Update  []struct {
				Name          string `xml:"name"`
				VersionString string `xml:"version_string"`
				ReleaseNotes  string `xml:"release_notes"`
			} `xml:"update"`
		} `xml:"release"`
	} `xml:"releases"`
}

type repomd struct {
	Data []struct {
		Type     string `xml:"type,attr"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
	} `xml:"data"`
}

type updates struct {
	Update []update `xml:"update"`
}

type update struct {
	ID      string `xml:"id"`
	Author  string `xml:"author,attr"`
	From    string `xml:"from,attr"`
	Status  string `xml:"status,attr"`
	Type    string `xml:"type,attr"`
	Version string `xml:"version,attr"`
	Title   string `xml:"title"`
	Issued  struct {
		Date string `xml:"date,attr"`
	} `xml:"issued"`
	Updated struct {
		Date string `xml:"date,attr"`
	} `xml:"updated"`
	Severity    string      `xml:"severity"`
	Description string      `xml:"description"`
	References  []Reference `xml:"references>reference"`
	Pkglist     struct {
		Short   string    `xml:"short,attr"`
		Name    string    `xml:"name"`
		Package []Package `xml:"package"`
	} `xml:"pkglist>collection"`
}

type Advisory struct {
	ID          string      `json:"id,omitempty"`
	Type        string      `json:"type,omitempty"`
	Author      string      `json:"author,omitempty"`
	From        string      `json:"from,omitempty"`
	Status      string      `json:"status,omitempty"`
	Version     string      `json:"version,omitempty"`
	Title       string      `json:"title,omitempty"`
	Description string      `json:"description,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Pkglist     Pkglist     `json:"pkglist,omitempty"`
	References  []Reference `json:"references,omitempty"`
	Issued      *time.Time  `json:"issued,omitempty"`
	Updated     *time.Time  `json:"updated,omitempty"`
}

type Pkglist struct {
	Short      string    `json:"short,omitempty"`
	Name       string    `json:"name,omitempty"`
	Repository string    `json:"repository,omitempty"`
	Package    []Package `json:"package,omitempty"`
}

type Package struct {
	Arch     string `xml:"arch,attr" json:"arch,omitempty"`
	Epoch    string `xml:"epoch,attr" json:"epoch,omitempty"`
	Name     string `xml:"name,attr" json:"name,omitempty"`
	Release  string `xml:"release,attr" json:"release,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Filename string `xml:"filename" json:"filename,omitempty"`
}

type Reference struct {
	Href  string `xml:"href,attr" json:"href,omitempty"`
	ID    string `xml:"id,attr" json:"id,omitempty"`
	Title string `xml:"title,attr" json:"title,omitempty"`
	Type  string `xml:"type,attr" json:"type,omitempty"`
}
