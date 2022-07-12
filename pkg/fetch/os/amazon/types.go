package amazon

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
	Update []Update `xml:"update"`
}

type Update struct {
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
	Severity    string `xml:"severity"`
	Description string `xml:"description"`
	References  struct {
		Reference []struct {
			Href  string `xml:"href,attr"`
			ID    string `xml:"id,attr"`
			Title string `xml:"title,attr"`
			Type  string `xml:"type,attr"`
		} `xml:"reference"`
	} `xml:"references"`
	Pkglist struct {
		Collection struct {
			Short   string `xml:"short,attr"`
			Name    string `xml:"name"`
			Package []struct {
				Arch     string `xml:"arch,attr"`
				Epoch    string `xml:"epoch,attr"`
				Name     string `xml:"name,attr"`
				Release  string `xml:"release,attr"`
				Version  string `xml:"version,attr"`
				Filename string `xml:"filename"`
			} `xml:"package"`
		} `xml:"collection"`
	} `xml:"pkglist"`
}
