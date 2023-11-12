package cvrf

import "time"

type updates struct {
	Value []struct {
		Alias              string    `json:"Alias"`
		CurrentReleaseDate time.Time `json:"CurrentReleaseDate"`
		CvrfURL            string    `json:"CvrfUrl"`
		DocumentTitle      string    `json:"DocumentTitle"`
		ID                 string    `json:"ID"`
		InitialReleaseDate time.Time `json:"InitialReleaseDate"`
	} `json:"value"`
}

type CVRF struct {
	DocumentTitle     string `xml:"DocumentTitle" json:"document_title,omitempty"`
	DocumentType      string `xml:"DocumentType" json:"document_type,omitempty"`
	DocumentPublisher struct {
		Type             string `xml:"Type,attr" json:"type,omitempty"`
		ContactDetails   string `xml:"ContactDetails" json:"contact_details,omitempty"`
		IssuingAuthority string `xml:"IssuingAuthority" json:"issuing_authority,omitempty"`
	} `xml:"DocumentPublisher" json:"documentpublisher,omitempty"`
	DocumentTracking DocumentTracking `xml:"DocumentTracking" json:"documenttracking,omitempty"`
	DocumentNotes    struct {
		Note []struct {
			Text     string `xml:",chardata" json:"text,omitempty"`
			Title    string `xml:"Title,attr" json:"title,omitempty"`
			Audience string `xml:"Audience,attr" json:"audience,omitempty"`
			Type     string `xml:"Type,attr" json:"type,omitempty"`
			Ordinal  string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
		} `xml:"Note" json:"note,omitempty"`
	} `xml:"DocumentNotes" json:"documentnotes,omitempty"`
	ProductTree   ProductTree     `xml:"ProductTree" json:"producttree,omitempty"`
	Vulnerability []Vulnerability `xml:"Vulnerability" json:"vulnerability,omitempty"`
}
type DocumentTracking struct {
	Identification  Identification `xml:"Identification" json:"identification,omitempty"`
	Status          string         `xml:"Status" json:"status,omitempty"`
	Version         string         `xml:"Version" json:"version,omitempty"`
	RevisionHistory struct {
		Revision struct {
			Number      string `xml:"Number" json:"number,omitempty"`
			Date        string `xml:"Date" json:"date,omitempty"`
			Description string `xml:"Description" json:"description,omitempty"`
		} `xml:"Revision" json:"revision,omitempty"`
	} `xml:"RevisionHistory" json:"revisionhistory,omitempty"`
	InitialReleaseDate string `xml:"InitialReleaseDate" json:"initial_release_date,omitempty"`
	CurrentReleaseDate string `xml:"CurrentReleaseDate" json:"current_release_date,omitempty"`
}

type Identification struct {
	ID    string `xml:"ID" json:"id,omitempty"`
	Alias string `xml:"Alias" json:"alias,omitempty"`
}

type ProductTree struct {
	Branch          Branch            `xml:"Branch" json:"branch,omitempty"`
	FullProductName []FullProductName `xml:"FullProductName" json:"fullproductname,omitempty"`
}

type Branch struct {
	Type            string            `xml:"Type,attr" json:"type,omitempty"`
	Name            string            `xml:"Name,attr" json:"name,omitempty"`
	FullProductName []FullProductName `xml:"FullProductName" json:"fullproductname,omitempty"`
	Branch          []Branch          `xml:"Branch" json:"branch,omitempty"`
}

type FullProductName struct {
	Text      string `xml:",chardata" json:"text,omitempty"`
	ProductID string `xml:"ProductID,attr" json:"productid,omitempty"`
}

type Vulnerability struct {
	Ordinal string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
	Title   string `xml:"Title" json:"title,omitempty"`
	Notes   struct {
		Note []struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Title   string `xml:"Title,attr" json:"title,omitempty"`
			Type    string `xml:"Type,attr" json:"type,omitempty"`
			Ordinal string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
		} `xml:"Note" json:"note,omitempty"`
	} `xml:"Notes" json:"notes,omitempty"`
	CVE             string `xml:"CVE" json:"cve,omitempty"`
	ProductStatuses struct {
		Status struct {
			Type      string   `xml:"Type,attr" json:"type,omitempty"`
			ProductID []string `xml:"ProductID" json:"product_id,omitempty"`
		} `xml:"Status" json:"status,omitempty"`
	} `xml:"ProductStatuses" json:"productstatuses,omitempty"`
	Threats struct {
		Threat []struct {
			Type        string `xml:"Type,attr" json:"type,omitempty"`
			Description string `xml:"Description" json:"description,omitempty"`
			ProductID   string `xml:"ProductID" json:"product_id,omitempty"`
		} `xml:"Threat" json:"threat,omitempty"`
	} `xml:"Threats" json:"threats,omitempty"`
	CVSSScoreSets struct {
		ScoreSet []struct {
			BaseScore     string `xml:"BaseScore" json:"base_score,omitempty"`
			TemporalScore string `xml:"TemporalScore" json:"temporal_score,omitempty"`
			Vector        string `xml:"Vector" json:"vector,omitempty"`
			ProductID     string `xml:"ProductID" json:"product_id,omitempty"`
		} `xml:"ScoreSet" json:"scoreset,omitempty"`
	} `xml:"CVSSScoreSets" json:"cvssscoresets,omitempty"`
	Remediations struct {
		Remediation []struct {
			Type          string   `xml:"Type,attr" json:"type,omitempty"`
			Description   string   `xml:"Description" json:"description,omitempty"`
			URL           string   `xml:"URL" json:"url,omitempty"`
			Supercedence  string   `xml:"Supercedence" json:"supercedence,omitempty"`
			ProductID     []string `xml:"ProductID" json:"product_id,omitempty"`
			AffectedFiles struct {
				AffectedFile []struct {
					FileName         string `xml:"FileName" json:"file_name,omitempty"`
					FileLastModified string `xml:"FileLastModified" json:"file_last_modified,omitempty"`
				} `xml:"AffectedFile" json:"affectedfile,omitempty"`
			} `xml:"AffectedFiles" json:"affectedfiles,omitempty"`
			RestartRequired string `xml:"RestartRequired" json:"restart_required,omitempty"`
			SubType         string `xml:"SubType" json:"sub_type,omitempty"`
			FixedBuild      string `xml:"FixedBuild" json:"fixed_build,omitempty"`
		} `xml:"Remediation" json:"remediation,omitempty"`
	} `xml:"Remediations" json:"remediations,omitempty"`
	Acknowledgments struct {
		Acknowledgment []struct {
			Name string `xml:"Name" json:"name,omitempty"`
			URL  string `xml:"URL" json:"url,omitempty"`
		} `xml:"Acknowledgment" json:"acknowledgment,omitempty"`
	} `xml:"Acknowledgments" json:"acknowledgments,omitempty"`
	RevisionHistory struct {
		Revision []struct {
			Number      string `xml:"Number" json:"number,omitempty"`
			Date        string `xml:"Date" json:"date,omitempty"`
			Description string `xml:"Description" json:"description,omitempty"`
		} `xml:"Revision" json:"revision,omitempty"`
	} `xml:"RevisionHistory" json:"revisionhistory,omitempty"`
}
