package gentoo

type GLSA struct {
	ID       string `xml:"id,attr"`
	Title    string `xml:"title"`
	Synopsis string `xml:"synopsis"`
	Product  struct {
		Text string `xml:",chardata"`
		Type string `xml:"type,attr"`
	} `xml:"product"`
	Announced string `xml:"announced"`
	Revised   struct {
		Text  string `xml:",chardata"`
		Count string `xml:"count,attr"`
	} `xml:"revised"`
	Bug      []string `xml:"bug"`
	Access   string   `xml:"access"`
	Affected struct {
		Package []struct {
			Name       string `xml:"name,attr"`
			Auto       string `xml:"auto,attr"`
			Arch       string `xml:"arch,attr"`
			Unaffected []struct {
				Text  string `xml:",chardata"`
				Range string `xml:"range,attr"`
				Slot  string `xml:"slot,attr"`
			} `xml:"unaffected"`
			Vulnerable []struct {
				Text  string `xml:",chardata"`
				Range string `xml:"range,attr"`
				Slot  string `xml:"slot,attr"`
			} `xml:"vulnerable"`
		} `xml:"package"`
		Service struct {
			Text  string `xml:",chardata"`
			Type  string `xml:"type,attr"`
			Fixed string `xml:"fixed,attr"`
		} `xml:"service"`
	} `xml:"affected"`
	Background struct {
		Text string `xml:",innerxml"`
	} `xml:"background"`
	Description struct {
		Text string `xml:",innerxml"`
	} `xml:"description"`
	Impact struct {
		Type string `xml:"type,attr"`
		Text string `xml:",innerxml"`
	} `xml:"impact"`
	Workaround struct {
		Text string `xml:",innerxml"`
	} `xml:"workaround"`
	Resolution struct {
		Text string `xml:",chardata"`
		P    []struct {
			Text string `xml:",chardata"`
			URI  struct {
				Text string `xml:",chardata"`
				Link string `xml:"link,attr"`
			} `xml:"uri"`
			Br   []string `xml:"br"`
			I    []string `xml:"i"`
			Code string   `xml:"code"`
			P    string   `xml:"p"`
		} `xml:"p"`
		Code []string `xml:"code"`
	} `xml:"resolution"`
	References struct {
		URI []struct {
			Text string `xml:",chardata"`
			Link string `xml:"link,attr"`
		} `xml:"uri"`
	} `xml:"references"`
	Metadata []struct {
		Text      string `xml:",chardata"`
		Tag       string `xml:"tag,attr"`
		Timestamp string `xml:"timestamp,attr"`
	} `xml:"metadata"`
}
