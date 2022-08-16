package cvrf

type CVRF struct {
	DocumentTitle     string `xml:"DocumentTitle" json:"document_title,omitempty"`
	DocumentType      string `xml:"DocumentType" json:"document_type,omitempty"`
	DocumentPublisher struct {
		Type             string `xml:"Type,attr" json:"type,omitempty"`
		ContactDetails   string `xml:"ContactDetails" json:"contact_details,omitempty"`
		IssuingAuthority string `xml:"IssuingAuthority" json:"issuing_authority,omitempty"`
	} `xml:"DocumentPublisher" json:"document_publisher,omitempty"`
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
		} `xml:"RevisionHistory" json:"revision_history,omitempty"`
		InitialReleaseDate string `xml:"InitialReleaseDate" json:"initial_release_date,omitempty"`
		CurrentReleaseDate string `xml:"CurrentReleaseDate" json:"current_release_date,omitempty"`
		Generator          struct {
			Engine string `xml:"Engine" json:"engine,omitempty"`
			Date   string `xml:"Date" json:"date,omitempty"`
		} `xml:"Generator" json:"generator,omitempty"`
	} `xml:"DocumentTracking" json:"document_tracking,omitempty"`
	DocumentNotes []struct {
		Text  string `xml:",chardata" json:"text,omitempty"`
		Title string `xml:"Title,attr" json:"title,omitempty"`
		Type  string `xml:"Type,attr" json:"type,omitempty"`
	} `xml:"DocumentNotes>Note" json:"document_notes,omitempty"`
	DocumentReferences []struct {
		Type        string `xml:"Type,attr" json:"type,omitempty"`
		URL         string `xml:"URL" json:"url,omitempty"`
		Description string `xml:"Description" json:"description,omitempty"`
	} `xml:"DocumentReferences>Reference" json:"document_references,omitempty"`
	ProductTree struct {
		Branch []struct {
			Type   string `xml:"Type,attr" json:"type,omitempty"`
			Name   string `xml:"Name,attr" json:"name,omitempty"`
			Branch []struct {
				Type            string `xml:"Type,attr" json:"type,omitempty"`
				Name            string `xml:"Name,attr" json:"name,omitempty"`
				FullProductName struct {
					Text      string `xml:",chardata" json:"text,omitempty"`
					ProductID string `xml:"ProductID,attr" json:"product_id,omitempty"`
					CPE       string `xml:"CPE,attr" json:"cpe,omitempty"`
				} `xml:"FullProductName" json:"full_product_name,omitempty"`
			} `xml:"Branch" json:"branch,omitempty"`
			FullProductName struct {
				Text      string `xml:",chardata" json:"text,omitempty"`
				ProductID string `xml:"ProductID,attr" json:"product_id,omitempty"`
			} `xml:"FullProductName" json:"full_product_name,omitempty"`
		} `xml:"Branch" json:"branch,omitempty"`
		Relationship []struct {
			ProductReference          string `xml:"ProductReference,attr" json:"product_reference,omitempty"`
			RelationType              string `xml:"RelationType,attr" json:"relation_type,omitempty"`
			RelatesToProductReference string `xml:"RelatesToProductReference,attr" json:"relates_to_product_reference,omitempty"`
		} `xml:"Relationship" json:"relationship,omitempty"`
	} `xml:"ProductTree" json:"product_tree,omitempty"`
	Vulnerability struct {
		Notes []struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Title string `xml:"Title,attr" json:"title,omitempty"`
			Type  string `xml:"Type,attr" json:"type,omitempty"`
		} `xml:"Notes>Note" json:"notes,omitempty"`
		CVE             string `xml:"CVE" json:"cve,omitempty"`
		ProductStatuses []struct {
			Type      string   `xml:"Type,attr" json:"type,omitempty"`
			ProductID []string `xml:"ProductID" json:"product_id,omitempty"`
		} `xml:"ProductStatuses>Status" json:"product_statuses,omitempty"`
		Threats []struct {
			Type        string `xml:"Type,attr" json:"type,omitempty"`
			Description string `xml:"Description" json:"description,omitempty"`
		} `xml:"Threats>Threat" json:"threats,omitempty"`
		CVSSScoreSets struct {
			ScoreSetV2 struct {
				BaseScoreV2 string `xml:"BaseScoreV2" json:"base_score_v_2,omitempty"`
				VectorV2    string `xml:"VectorV2" json:"vector_v_2,omitempty"`
			} `xml:"ScoreSetV2" json:"score_set_v_2,omitempty"`
			ScoreSetV3 struct {
				BaseScoreV3 string `xml:"BaseScoreV3" json:"base_score_v_3,omitempty"`
				VectorV3    string `xml:"VectorV3" json:"vector_v_3,omitempty"`
			} `xml:"ScoreSetV3" json:"score_set_v_3,omitempty"`
		} `xml:"CVSSScoreSets" json:"cvss_score_sets,omitempty"`
	} `xml:"Vulnerability" json:"vulnerability,omitempty"`
}
