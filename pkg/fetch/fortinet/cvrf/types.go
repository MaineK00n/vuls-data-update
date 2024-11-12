package cvrf

type CVRF struct {
	DocumentTitle     string `xml:"DocumentTitle" json:"document_title,omitempty"`
	DocumentType      string `xml:"DocumentType" json:"document_type,omitempty"`
	DocumentPublisher struct {
		Type           string `xml:"Type,attr" json:"type,omitempty"`
		ContactDetails string `xml:"ContactDetails" json:"contact_details,omitempty"`
	} `xml:"DocumentPublisher" json:"documentpublisher,omitempty"`
	DocumentTracking struct {
		Identification struct {
			ID string `xml:"ID" json:"id,omitempty"`
		} `xml:"Identification" json:"identification,omitempty"`
		Status          string `xml:"Status" json:"status,omitempty"`
		Version         string `xml:"Version" json:"version,omitempty"`
		RevisionHistory struct {
			Revision struct {
				Number      string `xml:"Number" json:"number,omitempty"`
				Date        string `xml:"Date" json:"date,omitempty"`
				Description string `xml:"Description" json:"description,omitempty"`
			} `xml:"Revision" json:"revision,omitempty"`
		} `xml:"RevisionHistory" json:"revisionhistory,omitempty"`
		InitialReleaseDate string `xml:"InitialReleaseDate" json:"initial_release_date,omitempty"`
		CurrentReleaseDate string `xml:"CurrentReleaseDate" json:"current_release_date,omitempty"`
	} `xml:"DocumentTracking" json:"documenttracking,omitempty"`
	DocumentNotes struct {
		Note []struct {
			Text    string `xml:",chardata" json:"text,omitempty"`
			Title   string `xml:"Title,attr" json:"title,omitempty"`
			Type    string `xml:"Type,attr" json:"type,omitempty"`
			Ordinal string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
		} `xml:"Note" json:"note,omitempty"`
	} `xml:"DocumentNotes" json:"documentnotes,omitempty"`
	DocumentReferences struct {
		Reference []struct {
			URL         string `xml:"URL" json:"url,omitempty"`
			Description string `xml:"Description" json:"description,omitempty"`
		} `xml:"Reference" json:"reference,omitempty"`
	} `xml:"DocumentReferences" json:"document_references,omitempty"`
	Acknowledgments struct {
		Acknowledgment []struct {
			Description string `xml:"Description" json:"description,omitempty"`
		} `xml:"Acknowledgment" json:"acknowledgment,omitempty"`
	} `xml:"Acknowledgments" json:"acknowledgments,omitempty"`
	Vulnerability struct {
		Ordinal    string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
		Title      string `xml:"Title" json:"title,omitempty"`
		References struct {
			Type      string `xml:"Type,attr" json:"type,omitempty"`
			Reference []struct {
				URL         string `xml:"URL" json:"url,omitempty"`
				Description string `xml:"Description" json:"description,omitempty"`
			} `xml:"Reference" json:"reference,omitempty"`
		} `xml:"References" json:"references,omitempty"`
		CVE             []string `xml:"CVE" json:"cve,omitempty"`
		ProductStatuses struct {
			Status struct {
				Type      string   `xml:"Type,attr" json:"type,omitempty"`
				ProductID []string `xml:"ProductID" json:"product_id,omitempty"`
			} `xml:"Status" json:"status,omitempty"`
		} `xml:"ProductStatuses" json:"product_statuses,omitempty"`
		CVSSScoreSets struct {
			ScoreSetV3 struct {
				BaseScoreV3 string `xml:"BaseScoreV3" json:"base_score_v3,omitempty"`
				VectorV3    string `xml:"VectorV3" json:"vector_v3,omitempty"`
			} `xml:"ScoreSetV3" json:"scoreset_v3,omitempty"`
		} `xml:"CVSSScoreSets" json:"cvss_scoresets,omitempty"`
	} `xml:"Vulnerability" json:"vulnerability,omitempty"`
	ProductTree struct {
		Branch struct {
			Name   string `xml:"Name,attr" json:"name,omitempty"`
			Type   string `xml:"Type,attr" json:"type,omitempty"`
			Branch []struct {
				Name   string `xml:"Name,attr" json:"name,omitempty"`
				Type   string `xml:"Type,attr" json:"type,omitempty"`
				Branch []struct {
					Name            string `xml:"Name,attr" json:"name,omitempty"`
					Type            string `xml:"Type,attr" json:"type,omitempty"`
					FullProductName struct {
						Text      string `xml:",chardata" json:"text,omitempty"`
						ProductID string `xml:"ProductID,attr" json:"product_id,omitempty"`
					} `xml:"FullProductName" json:"full_product_name,omitempty"`
				} `xml:"Branch" json:"branch,omitempty"`
			} `xml:"Branch" json:"branch,omitempty"`
		} `xml:"Branch" json:"branch,omitempty"`
	} `xml:"ProductTree" json:"product_tree,omitempty"`
}
