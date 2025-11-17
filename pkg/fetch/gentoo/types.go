package gentoo

type GLSA struct {
	ID       string `xml:"id,attr" json:"ID,omitempty"`
	Title    string `xml:"title" json:"Title,omitempty"`
	Synopsis string `xml:"synopsis" json:"Synopsis,omitempty"`
	Product  struct {
		Text string `xml:",chardata" json:"Text,omitempty"`
		Type string `xml:"type,attr" json:"Type,omitempty"`
	} `xml:"product" json:"Product,omitzero"`
	Announced string `xml:"announced" json:"Announced,omitempty"`
	Revised   struct {
		Text  string `xml:",chardata" json:"Text,omitempty"`
		Count string `xml:"count,attr" json:"Count,omitempty"`
	} `xml:"revised" json:"Revised,omitzero"`
	Bug      []string `xml:"bug" json:"Bug,omitempty"`
	Access   string   `xml:"access" json:"Access,omitempty"`
	Affected struct {
		Package []struct {
			Name       string `xml:"name,attr" json:"Name,omitempty"`
			Auto       string `xml:"auto,attr" json:"Auto,omitempty"`
			Arch       string `xml:"arch,attr" json:"Arch,omitempty"`
			Unaffected []struct {
				Text  string `xml:",chardata" json:"Text,omitempty"`
				Range string `xml:"range,attr" json:"Range,omitempty"`
				Slot  string `xml:"slot,attr" json:"Slot,omitempty"`
			} `xml:"unaffected" json:"Unaffected,omitempty"`
			Vulnerable []struct {
				Text  string `xml:",chardata" json:"Text,omitempty"`
				Range string `xml:"range,attr" json:"Range,omitempty"`
				Slot  string `xml:"slot,attr" json:"Slot,omitempty"`
			} `xml:"vulnerable" json:"Vulnerable,omitempty"`
		} `xml:"package" json:"Package,omitempty"`
		Service struct {
			Text  string `xml:",chardata" json:"Text,omitempty"`
			Type  string `xml:"type,attr" json:"Type,omitempty"`
			Fixed string `xml:"fixed,attr" json:"Fixed,omitempty"`
		} `xml:"service" json:"Service,omitzero"`
	} `xml:"affected" json:"Affected,omitzero"`
	Background struct {
		Text string `xml:",innerxml" json:"Text,omitempty"`
	} `xml:"background" json:"Background,omitzero"`
	Description struct {
		Text string `xml:",innerxml" json:"Text,omitempty"`
	} `xml:"description" json:"Description,omitzero"`
	Impact struct {
		Type string `xml:"type,attr" json:"Type,omitempty"`
		Text string `xml:",innerxml" json:"Text,omitempty"`
	} `xml:"impact" json:"Impact,omitzero"`
	Workaround struct {
		Text string `xml:",innerxml" json:"Text,omitempty"`
	} `xml:"workaround" json:"Workaround,omitzero"`
	Resolution struct {
		Text string `xml:",chardata" json:"Text,omitempty"`
		P    []struct {
			Text string `xml:",chardata" json:"Text,omitempty"`
			URI  struct {
				Text string `xml:",chardata" json:"Text,omitempty"`
				Link string `xml:"link,attr" json:"Link,omitempty"`
			} `xml:"uri" json:"URI,omitzero"`
			Br   []string `xml:"br" json:"Br,omitempty"`
			I    []string `xml:"i" json:"I,omitempty"`
			Code string   `xml:"code" json:"Code,omitempty"`
			P    string   `xml:"p" json:"P,omitempty"`
		} `xml:"p" json:"P,omitempty"`
		Code []string `xml:"code" json:"Code,omitempty"`
	} `xml:"resolution" json:"Resolution,omitzero"`
	References struct {
		URI []struct {
			Text string `xml:",chardata" json:"Text,omitempty"`
			Link string `xml:"link,attr" json:"Link,omitempty"`
		} `xml:"uri" json:"URI,omitempty"`
	} `xml:"references" json:"References,omitzero"`
	Metadata []struct {
		Text      string `xml:",chardata" json:"Text,omitempty"`
		Tag       string `xml:"tag,attr" json:"Tag,omitempty"`
		Timestamp string `xml:"timestamp,attr" json:"Timestamp,omitempty"`
	} `xml:"metadata" json:"Metadata,omitempty"`
}
