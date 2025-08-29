package cwe

type weaknessCatalog struct {
	Weaknesses         []weakness          `xml:"Weaknesses>Weakness"`
	Categories         []category          `xml:"Categories>Category"`
	Views              []view              `xml:"Views>View"`
	ExternalReferences []ExternalReference `xml:"External_References>External_Reference"`
}

type weakness struct {
	ID                  string `xml:"ID,attr"`
	Name                string `xml:"Name,attr"`
	Abstraction         string `xml:"Abstraction,attr"`
	Structure           string `xml:"Structure,attr"`
	Status              string `xml:"Status,attr"`
	Description         string `xml:"Description"`
	ExtendedDescription struct {
		Text string `xml:",innerxml"`
	} `xml:"Extended_Description"`
	RelatedWeaknesses   []RelatedWeakness   `xml:"Related_Weaknesses>Related_Weakness"`
	ApplicablePlatforms ApplicablePlatforms `xml:"Applicable_Platforms"`
	BackgroundDetails   []struct {
		Text string `xml:",innerxml"`
	} `xml:"Background_Details>Background_Detail"`
	ModesOfIntroduction []struct {
		Phase string `xml:"Phase"`
		Note  []struct {
			Text string `xml:",innerxml"`
		} `xml:"Note"`
	} `xml:"Modes_Of_Introduction>Introduction"`
	LikelihoodOfExploit  string              `xml:"Likelihood_Of_Exploit"`
	CommonConsequences   []CommonConsequence `xml:"Common_Consequences>Consequence"`
	PotentialMitigations []struct {
		MitigationID string   `xml:"Mitigation_ID,attr"`
		Phase        []string `xml:"Phase"`
		Description  []struct {
			Text string `xml:",innerxml"`
		} `xml:"Description"`
		Effectiveness      string `xml:"Effectiveness"`
		EffectivenessNotes string `xml:"Effectiveness_Notes"`
		Strategy           string `xml:"Strategy"`
	} `xml:"Potential_Mitigations>Mitigation"`
	DemonstrativeExamples []DemonstrativeExample `xml:"Demonstrative_Examples>Demonstrative_Example"`
	ObservedExamples      []ObservedExample      `xml:"Observed_Examples>Observed_Example"`
	References            []struct {
		ExternalReferenceID string `xml:"External_Reference_ID,attr" json:"external_reference_id,omitempty"`
		Section             string `xml:"Section,attr" json:"section,omitempty"`
	} `xml:"References>Reference"`
	ContentHistory struct {
		Submission struct {
			SubmissionName         string `xml:"Submission_Name"`
			SubmissionOrganization string `xml:"Submission_Organization"`
			SubmissionDate         string `xml:"Submission_Date"`
			SubmissionComment      string `xml:"Submission_Comment"`
		} `xml:"Submission"`
		Modification []struct {
			ModificationName         string `xml:"Modification_Name"`
			ModificationOrganization string `xml:"Modification_Organization"`
			ModificationDate         string `xml:"Modification_Date"`
			ModificationComment      string `xml:"Modification_Comment"`
			ModificationImportance   string `xml:"Modification_Importance"`
		} `xml:"Modification"`
		PreviousEntryName []struct {
			Text string `xml:",chardata"`
			Date string `xml:"Date,attr"`
		} `xml:"Previous_Entry_Name"`
		Contribution []struct {
			Type                     string `xml:"Type,attr"`
			ContributionName         string `xml:"Contribution_Name"`
			ContributionOrganization string `xml:"Contribution_Organization"`
			ContributionDate         string `xml:"Contribution_Date"`
			ContributionComment      string `xml:"Contribution_Comment"`
		} `xml:"Contribution"`
	} `xml:"Content_History"`
	WeaknessOrdinalities []WeaknessOrdinality `xml:"Weakness_Ordinalities>Weakness_Ordinality"`
	AlternateTerms       []struct {
		Term        string `xml:"Term"`
		Description struct {
			Text string `xml:",innerxml"`
		} `xml:"Description"`
	} `xml:"Alternate_Terms>Alternate_Term"`
	DetectionMethods []struct {
		DetectionMethodID string `xml:"Detection_Method_ID,attr"`
		Method            string `xml:"Method"`
		Description       struct {
			Text string `xml:",innerxml"`
		} `xml:"Description"`
		Effectiveness      string `xml:"Effectiveness"`
		EffectivenessNotes string `xml:"Effectiveness_Notes"`
	} `xml:"Detection_Methods>Detection_Method"`
	TaxonomyMappings      []TaxonomyMappings `xml:"Taxonomy_Mappings>Taxonomy_Mapping"`
	RelatedAttackPatterns []struct {
		CAPECID string `xml:"CAPEC_ID,attr"`
	} `xml:"Related_Attack_Patterns>Related_Attack_Pattern"`
	Notes             []Note   `xml:"Notes>Note"`
	AffectedResources []string `xml:"Affected_Resources>Affected_Resource"`
	FunctionalAreas   []string `xml:"Functional_Areas>Functional_Area"`
}

type category struct {
	ID             string `xml:"ID,attr"`
	Name           string `xml:"Name,attr"`
	Status         string `xml:"Status,attr"`
	Summary        string `xml:"Summary"`
	ContentHistory struct {
		Submission struct {
			SubmissionName         string `xml:"Submission_Name"`
			SubmissionOrganization string `xml:"Submission_Organization"`
			SubmissionDate         string `xml:"Submission_Date"`
			SubmissionComment      string `xml:"Submission_Comment"`
		} `xml:"Submission"`
		Modification []struct {
			ModificationName         string `xml:"Modification_Name"`
			ModificationOrganization string `xml:"Modification_Organization"`
			ModificationDate         string `xml:"Modification_Date"`
			ModificationComment      string `xml:"Modification_Comment"`
			ModificationImportance   string `xml:"Modification_Importance"`
		} `xml:"Modification"`
		PreviousEntryName []struct {
			Text string `xml:",chardata"`
			Date string `xml:"Date,attr"`
		} `xml:"Previous_Entry_Name"`
		Contribution []struct {
			Type                     string `xml:"Type,attr"`
			ContributionName         string `xml:"Contribution_Name"`
			ContributionOrganization string `xml:"Contribution_Organization"`
			ContributionDate         string `xml:"Contribution_Date"`
			ContributionComment      string `xml:"Contribution_Comment"`
		} `xml:"Contribution"`
	} `xml:"Content_History"`
	Relationships []HasMember `xml:"Relationships>Has_Member"`
	References    []struct {
		ExternalReferenceID string `xml:"External_Reference_ID,attr" json:"external_reference_id,omitempty"`
		Section             string `xml:"Section,attr" json:"section,omitempty"`
	} `xml:"References>Reference"`
	Notes            []Note            `xml:"Notes>Note"`
	TaxonomyMappings []TaxonomyMapping `xml:"Taxonomy_Mappings>Taxonomy_Mapping"`
}

type view struct {
	ID             string      `xml:"ID,attr"`
	Name           string      `xml:"Name,attr"`
	Type           string      `xml:"Type,attr"`
	Status         string      `xml:"Status,attr"`
	Objective      string      `xml:"Objective"`
	Audience       []Audience  `xml:"Audience>Stakeholder"`
	Members        []HasMember `xml:"Members>Has_Member"`
	Notes          []Note      `xml:"Notes>Note"`
	ContentHistory struct {
		Submission struct {
			SubmissionName         string `xml:"Submission_Name"`
			SubmissionOrganization string `xml:"Submission_Organization"`
			SubmissionDate         string `xml:"Submission_Date"`
			SubmissionComment      string `xml:"Submission_Comment"`
		} `xml:"Submission"`
		Modification []struct {
			ModificationName         string `xml:"Modification_Name"`
			ModificationOrganization string `xml:"Modification_Organization"`
			ModificationDate         string `xml:"Modification_Date"`
			ModificationComment      string `xml:"Modification_Comment"`
			ModificationImportance   string `xml:"Modification_Importance"`
		} `xml:"Modification"`
		PreviousEntryName []struct {
			Text string `xml:",chardata"`
			Date string `xml:"Date,attr"`
		} `xml:"Previous_Entry_Name"`
		Contribution []struct {
			Type                     string `xml:"Type,attr"`
			ContributionName         string `xml:"Contribution_Name"`
			ContributionOrganization string `xml:"Contribution_Organization"`
			ContributionDate         string `xml:"Contribution_Date"`
			ContributionComment      string `xml:"Contribution_Comment"`
		} `xml:"Contribution"`
	} `xml:"Content_History"`
	References []struct {
		ExternalReferenceID string `xml:"External_Reference_ID,attr" json:"external_reference_id,omitempty"`
		Section             string `xml:"Section,attr" json:"section,omitempty"`
	} `xml:"References>Reference"`
	Filter string `xml:"Filter"`
}

type Weakness struct {
	ID                    string                 `json:"id,omitempty"`
	Name                  string                 `json:"name,omitempty"`
	Abstraction           string                 `json:"abstraction,omitempty"`
	Structure             string                 `json:"structure,omitempty"`
	Status                string                 `json:"status,omitempty"`
	Description           string                 `json:"description,omitempty"`
	ExtendedDescription   string                 `json:"extended_description,omitempty"`
	RelatedWeaknesses     []RelatedWeakness      `json:"related_weaknesses,omitempty"`
	ApplicablePlatforms   ApplicablePlatforms    `json:"applicable_platforms,omitempty"`
	BackgroundDetails     []string               `json:"background_details,omitempty"`
	ModesOfIntroduction   []ModesOfIntroduction  `json:"modes_of_introduction,omitempty"`
	LikelihoodOfExploit   string                 `json:"likelihood_of_exploit,omitempty"`
	CommonConsequences    []CommonConsequence    `json:"common_consequences,omitempty"`
	PotentialMitigations  []PotentialMitigation  `json:"potential_mitigations,omitempty"`
	DemonstrativeExamples []DemonstrativeExample `json:"demonstrative_examples,omitempty"`
	ObservedExamples      []ObservedExample      `json:"observed_examples,omitempty"`
	References            []Reference            `json:"references,omitempty"`
	ContentHistory        ContentHistory         `json:"content_history,omitempty"`
	WeaknessOrdinalities  []WeaknessOrdinality   `json:"weakness_ordinalities,omitempty"`
	AlternateTerms        []AlternateTerm        `json:"alternate_terms,omitempty"`
	DetectionMethods      []DetectionMethods     `json:"detection_methods,omitempty"`
	TaxonomyMappings      []TaxonomyMappings     `json:"taxonomy_mappings,omitempty"`
	RelatedAttackPatterns []string               `json:"related_attack_patterns,omitempty"`
	Notes                 []Note                 `json:"notes,omitempty"`
	AffectedResources     []string               `json:"affected_resources,omitempty"`
	FunctionalAreas       []string               `json:"functional_areas,omitempty"`
}

type RelatedWeakness struct {
	Nature  string `xml:"Nature,attr" json:"nature,omitempty"`
	CWEID   string `xml:"CWE_ID,attr" json:"cweid,omitempty"`
	ViewID  string `xml:"View_ID,attr" json:"view_id,omitempty"`
	Ordinal string `xml:"Ordinal,attr" json:"ordinal,omitempty"`
	ChainID string `xml:"Chain_ID,attr" json:"chain_id,omitempty"`
}

type ApplicablePlatforms struct {
	Language        []ApplicablePlatform `xml:"Language" json:"language,omitempty"`
	Technology      []ApplicablePlatform `xml:"Technology" json:"technology,omitempty"`
	OperatingSystem []ApplicablePlatform `xml:"Operating_System" json:"operating_system,omitempty"`
	Architecture    []ApplicablePlatform `xml:"Architecture" json:"architecture,omitempty"`
}

type ApplicablePlatform struct {
	Class      string `xml:"Class,attr" json:"class,omitempty"`
	Prevalence string `xml:"Prevalence,attr" json:"prevalence,omitempty"`
	Name       string `xml:"Name,attr" json:"name,omitempty"`
}

type ModesOfIntroduction struct {
	Phase string   `json:"phase,omitempty"`
	Note  []string `json:"note,omitempty"`
}

type CommonConsequence struct {
	Scope      []string `xml:"Scope" json:"scope,omitempty"`
	Impact     []string `xml:"Impact" json:"impact,omitempty"`
	Note       string   `xml:"Note" json:"note,omitempty"`
	Likelihood string   `xml:"Likelihood" json:"likelihood,omitempty"`
}

type PotentialMitigation struct {
	MitigationID       string   `json:"mitigation_id,omitempty"`
	Phase              []string `json:"phase,omitempty"`
	Description        []string `json:"description,omitempty"`
	Effectiveness      string   `json:"effectiveness,omitempty"`
	EffectivenessNotes string   `json:"effectiveness_notes,omitempty"`
	Strategy           string   `json:"strategy,omitempty"`
}

type DemonstrativeExample struct {
	DemonstrativeExampleID string `xml:"Demonstrative_Example_ID,attr" json:"demonstrative_example_id,omitempty"`
	Text                   string `xml:",innerxml" json:"text,omitempty"`
}

type ObservedExample struct {
	Reference   string `xml:"Reference" json:"reference,omitempty"`
	Description string `xml:"Description" json:"description,omitempty"`
	Link        string `xml:"Link" json:"link,omitempty"`
}

type Reference struct {
	Section string `xml:"Section,attr" json:"section,omitempty"`
	ExternalReference
}

type ContentHistory struct {
	Submission        Submission          `json:"submission,omitempty"`
	Modification      []Modification      ` json:"modification,omitempty"`
	PreviousEntryName []PreviousEntryName ` json:"previous_entry_name,omitempty"`
	Contribution      []Contribution      `json:"contribution,omitempty"`
}

type Submission struct {
	SubmissionName         string `json:"submission_name,omitempty"`
	SubmissionOrganization string `json:"submission_organization,omitempty"`
	SubmissionDate         string `json:"submission_date,omitempty"`
	SubmissionComment      string `json:"submission_comment,omitempty"`
}

type Modification struct {
	ModificationName         string `json:"modification_name,omitempty"`
	ModificationOrganization string `json:"modification_organization,omitempty"`
	ModificationDate         string `json:"modification_date,omitempty"`
	ModificationComment      string `json:"modification_comment,omitempty"`
	ModificationImportance   string `json:"modification_importance,omitempty"`
}

type PreviousEntryName struct {
	Text string `json:"text,omitempty"`
	Date string `json:"date,omitempty"`
}

type Contribution struct {
	Type                     string `json:"type,omitempty"`
	ContributionName         string `json:"contribution_name,omitempty"`
	ContributionOrganization string `json:"contribution_organization,omitempty"`
	ContributionDate         string `json:"contribution_date,omitempty"`
	ContributionComment      string `json:"contribution_comment,omitempty"`
}

type WeaknessOrdinality struct {
	Ordinality  string `xml:"Ordinality" json:"ordinality,omitempty"`
	Description string `xml:"Description" json:"description,omitempty"`
}

type AlternateTerm struct {
	Term        string `json:"term,omitempty"`
	Description string `json:"description,omitempty"`
}

type DetectionMethods struct {
	DetectionMethodID  string `json:"detection_method_id,omitempty"`
	Method             string `json:"method,omitempty"`
	Description        string `json:"description,omitempty"`
	Effectiveness      string `json:"effectiveness,omitempty"`
	EffectivenessNotes string `json:"effectiveness_notes,omitempty"`
}

type TaxonomyMappings struct {
	TaxonomyName string `xml:"Taxonomy_Name,attr" json:"taxonomy_name,omitempty"`
	EntryName    string `xml:"Entry_Name" json:"entry_name,omitempty"`
	EntryID      string `xml:"Entry_ID" json:"entry_id,omitempty"`
	MappingFit   string `xml:"Mapping_Fit" json:"mapping_fit,omitempty"`
}

type Note struct {
	Type string `xml:"Type,attr" json:"type,omitempty"`
	Text string `xml:",innerxml" json:"text,omitempty"`
}

type Category struct {
	ID               string            `json:"id,omitempty"`
	Name             string            `json:"name,omitempty"`
	Status           string            `json:"status,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	ContentHistory   ContentHistory    `json:"content_history,omitempty"`
	Relationships    []HasMember       `json:"relationships,omitempty"`
	References       []Reference       `json:"references,omitempty"`
	Notes            []Note            `json:"notes,omitempty"`
	TaxonomyMappings []TaxonomyMapping `json:"taxonomy_mappings,omitempty"`
}

type HasMember struct {
	CWEID  string `xml:"CWE_ID,attr" json:"cweid,omitempty"`
	ViewID string `xml:"View_ID,attr" json:"view_id,omitempty"`
}

type TaxonomyMapping struct {
	TaxonomyName string `xml:"Taxonomy_Name,attr" json:"taxonomy_name,omitempty"`
	EntryID      string `xml:"Entry_ID" json:"entry_id,omitempty"`
	EntryName    string `xml:"Entry_Name" json:"entry_name,omitempty"`
	MappingFit   string `xml:"Mapping_Fit" json:"mapping_fit,omitempty"`
}

type View struct {
	ID             string         `json:"id,omitempty"`
	Name           string         `json:"name,omitempty"`
	Type           string         `json:"type,omitempty"`
	Status         string         `json:"status,omitempty"`
	Objective      string         `json:"objective,omitempty"`
	Audience       []Audience     `json:"audience,omitempty"`
	Members        []HasMember    `json:"members,omitempty"`
	Notes          []Note         `json:"notes,omitempty"`
	ContentHistory ContentHistory `json:"content_history,omitempty"`
	References     []Reference    `json:"references,omitempty"`
	Filter         string         `json:"filter,omitempty"`
}

type Audience struct {
	Type        string `xml:"Type" json:"type,omitempty"`
	Description string `xml:"Description" json:"description,omitempty"`
}

type ExternalReference struct {
	ReferenceID      string   `xml:"Reference_ID,attr" json:"reference_id,omitempty"`
	Author           []string `xml:"Author" json:"author,omitempty"`
	Title            string   `xml:"Title" json:"title,omitempty"`
	URL              string   `xml:"URL" json:"url,omitempty"`
	PublicationYear  string   `xml:"Publication_Year" json:"publication_year,omitempty"`
	PublicationMonth string   `xml:"Publication_Month" json:"publication_month,omitempty"`
	PublicationDay   string   `xml:"Publication_Day" json:"publication_day,omitempty"`
	Publication      string   `xml:"Publication" json:"publication,omitempty"`
	Publisher        string   `xml:"Publisher" json:"publisher,omitempty"`
	Edition          string   `xml:"Edition" json:"edition,omitempty"`
	URLDate          string   `xml:"URL_Date" json:"url_date,omitempty"`
}
