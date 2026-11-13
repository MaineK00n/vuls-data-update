package cwe

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"

	"github.com/pkg/errors"
)

// structuredText decodes an element of the schema's StructuredTextType, whose
// content is either plain text or XHTML. Decoded into a plain string, such an
// element keeps only the character data directly inside it, so an XHTML body
// is reduced to the whitespace between its tags.
//
// Plain text keeps the decoded character data. XHTML is kept as the raw inner
// XML, the way the ",innerxml" fields (Extended_Description,
// Background_Detail, ...) keep it. Raw XML has a '<' only where markup opens,
// since character data escapes it as "&lt;", so a '<' tells the two apart.
// Taking the raw inner XML of plain text as well would hand out its entities
// undecoded ("Information &amp; Software").
type structuredText struct {
	InnerXML string `xml:",innerxml"`
	CharData string `xml:",chardata"`
}

func (t structuredText) String() string {
	if strings.Contains(t.InnerXML, "<") {
		return t.InnerXML
	}
	return t.CharData
}

// OneOrMany is a list that also decodes from a single JSON value. Schema v8.0
// (CWE 5.0) made a few elements repeatable, and raw files written before they
// were read as lists hold a single value there; the extractor still reads
// such files until the next fetch rewrites them.
type OneOrMany[T any] []T

func (o *OneOrMany[T]) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	switch dec.PeekKind() {
	case 'n':
		if _, err := dec.ReadToken(); err != nil {
			return errors.Wrap(err, "read null")
		}
		*o = nil
	case '[':
		var l []T
		if err := json.UnmarshalDecode(dec, &l); err != nil {
			return errors.Wrap(err, "decode list")
		}
		*o = l
	default:
		var v T
		if err := json.UnmarshalDecode(dec, &v); err != nil {
			return errors.Wrap(err, "decode single value")
		}
		*o = OneOrMany[T]{v}
	}
	return nil
}

// CWE 5.0 (schema v8.0) renamed Categories>Category to Groupings>Grouping.
// They are still written as categories, so the raw layout is unchanged.
type weaknessCatalog struct {
	Weaknesses         []weakness          `xml:"Weaknesses>Weakness"`
	Categories         []category          `xml:"Groupings>Grouping"`
	Views              []view              `xml:"Views>View"`
	ExternalReferences []ExternalReference `xml:"External_References>External_Reference"`
}

type weakness struct {
	ID                  string `xml:"ID,attr"`
	Name                string `xml:"Name,attr"`
	Abstraction         string `xml:"Abstraction,attr"`
	Structure           string `xml:"Structure,attr"`
	Status              string `xml:"Status,attr"`
	Diagram             string `xml:"Diagram,attr"`
	Description         string `xml:"Description"`
	ExtendedDescription struct {
		Text string `xml:",innerxml"`
	} `xml:"Extended_Description"`
	TechnicalNuance     structuredText      `xml:"Technical_Nuance"`
	Dimensions          []Dimension         `xml:"Dimensions>Dimension"`
	RelatedWeaknesses   []RelatedWeakness   `xml:"Related_Weaknesses>Related_Weakness"`
	ApplicablePlatforms applicablePlatforms `xml:"Applicable_Platforms"`
	BackgroundDetails   []struct {
		Text string `xml:",innerxml"`
	} `xml:"Background_Details>Background_Detail"`
	ModesOfIntroduction []struct {
		Phase       []string      `xml:"Phase"`
		CustomPhase []CustomPhase `xml:"Custom_Phase"`
		Note        []struct {
			Text string `xml:",innerxml"`
		} `xml:"Note"`
	} `xml:"Modes_Of_Introduction>Introduction"`
	LikelihoodOfExploit  string        `xml:"Likelihood_Of_Exploit"`
	CommonConsequences   []consequence `xml:"Common_Consequences>Consequence"`
	PotentialMitigations []struct {
		MitigationID string        `xml:"Mitigation_ID,attr"`
		Phase        []string      `xml:"Phase"`
		CustomPhase  []CustomPhase `xml:"Custom_Phase"`
		Description  []struct {
			Text string `xml:",innerxml"`
		} `xml:"Description"`
		Effectiveness      string         `xml:"Effectiveness"`
		EffectivenessNotes structuredText `xml:"Effectiveness_Notes"`
		Strategy           string         `xml:"Strategy"`
	} `xml:"Potential_Mitigations>Mitigation"`
	DemonstrativeExamples []DemonstrativeExample `xml:"Demonstrative_Examples>Demonstrative_Example"`
	ObservedExamples      []observedExample      `xml:"Observed_Examples>Observed_Example"`
	References            []struct {
		ExternalReferenceID string `xml:"External_Reference_ID,attr" json:"external_reference_id,omitempty"`
		Section             string `xml:"Section,attr" json:"section,omitempty"`
	} `xml:"References>Reference"`
	ContentHistory       contentHistory       `xml:"Content_History"`
	WeaknessOrdinalities []WeaknessOrdinality `xml:"Weakness_Ordinalities>Weakness_Ordinality"`
	AlternateTerms       []struct {
		Term        string   `xml:"Term"`
		Role        []string `xml:"Role"`
		Description struct {
			Text string `xml:",innerxml"`
		} `xml:"Description"`
	} `xml:"Alternate_Terms>Alternate_Term"`
	DetectionMethods []struct {
		DetectionMethodID string        `xml:"Detection_Method_ID,attr"`
		Method            string        `xml:"Method"`
		Phase             []string      `xml:"Phase"`
		CustomPhase       []CustomPhase `xml:"Custom_Phase"`
		Description       struct {
			Text string `xml:",innerxml"`
		} `xml:"Description"`
		Effectiveness      string         `xml:"Effectiveness"`
		EffectivenessNotes structuredText `xml:"Effectiveness_Notes"`
	} `xml:"Detection_Methods>Detection_Method"`
	TaxonomyMappings      []TaxonomyMappings `xml:"Taxonomy_Mappings>Taxonomy_Mapping"`
	RelatedAttackPatterns []struct {
		CAPECID string `xml:"CAPEC_ID,attr"`
	} `xml:"Related_Attack_Patterns>Related_Attack_Pattern"`
	Notes             []Note       `xml:"Notes>Note"`
	AffectedResources []string     `xml:"Affected_Resources>Affected_Resource"`
	FunctionalAreas   []string     `xml:"Functional_Areas>Functional_Area"`
	MappingNotes      mappingNotes `xml:"Mapping_Notes"`
}

type category struct {
	ID             string         `xml:"ID,attr"`
	Name           string         `xml:"Name,attr"`
	Status         string         `xml:"Status,attr"`
	Summary        structuredText `xml:"Summary"`
	ContentHistory contentHistory `xml:"Content_History"`
	Relationships  []HasMember    `xml:"Relationships>Has_Member"`
	References     []struct {
		ExternalReferenceID string `xml:"External_Reference_ID,attr" json:"external_reference_id,omitempty"`
		Section             string `xml:"Section,attr" json:"section,omitempty"`
	} `xml:"References>Reference"`
	Notes            []Note            `xml:"Notes>Note"`
	TaxonomyMappings []TaxonomyMapping `xml:"Taxonomy_Mappings>Taxonomy_Mapping"`
	MappingNotes     mappingNotes      `xml:"Mapping_Notes"`
}

type view struct {
	ID             string         `xml:"ID,attr"`
	Name           string         `xml:"Name,attr"`
	Type           string         `xml:"Type,attr"`
	Status         string         `xml:"Status,attr"`
	Objective      structuredText `xml:"Objective"`
	Audience       []Audience     `xml:"Audience>Stakeholder"`
	Members        []HasMember    `xml:"Members>Has_Member"`
	Notes          []Note         `xml:"Notes>Note"`
	ContentHistory contentHistory `xml:"Content_History"`
	References     []struct {
		ExternalReferenceID string `xml:"External_Reference_ID,attr" json:"external_reference_id,omitempty"`
		Section             string `xml:"Section,attr" json:"section,omitempty"`
	} `xml:"References>Reference"`
	Filter       string       `xml:"Filter"`
	MappingNotes mappingNotes `xml:"Mapping_Notes"`
}

// contentHistory is the ContentHistoryType shared by weaknesses, categories
// and views. Since schema v8.0 an entry may have several submissions, a
// submission or contribution several names, and every record the CWE version
// and release date it first appeared in.
type contentHistory struct {
	Submission []struct {
		SubmissionName         []string `xml:"Submission_Name"`
		SubmissionOrganization string   `xml:"Submission_Organization"`
		SubmissionDate         string   `xml:"Submission_Date"`
		SubmissionVersion      string   `xml:"Submission_Version"`
		SubmissionReleaseDate  string   `xml:"Submission_ReleaseDate"`
		SubmissionComment      string   `xml:"Submission_Comment"`
	} `xml:"Submission"`
	Modification []struct {
		ModificationName         string `xml:"Modification_Name"`
		ModificationOrganization string `xml:"Modification_Organization"`
		ModificationDate         string `xml:"Modification_Date"`
		ModificationVersion      string `xml:"Modification_Version"`
		ModificationReleaseDate  string `xml:"Modification_ReleaseDate"`
		ModificationComment      string `xml:"Modification_Comment"`
		ModificationImportance   string `xml:"Modification_Importance"`
	} `xml:"Modification"`
	PreviousEntryName []struct {
		Text    string `xml:",chardata"`
		Date    string `xml:"Date,attr"`
		Version string `xml:"Version,attr"`
	} `xml:"Previous_Entry_Name"`
	Contribution []struct {
		Type                     string   `xml:"Type,attr"`
		ContributionName         []string `xml:"Contribution_Name"`
		ContributionOrganization string   `xml:"Contribution_Organization"`
		ContributionDate         string   `xml:"Contribution_Date"`
		ContributionVersion      string   `xml:"Contribution_Version"`
		ContributionReleaseDate  string   `xml:"Contribution_ReleaseDate"`
		ContributionComment      string   `xml:"Contribution_Comment"`
	} `xml:"Contribution"`
}

type mappingNotes struct {
	Usage     string         `xml:"Usage"`
	Rationale structuredText `xml:"Rationale"`
	Comments  structuredText `xml:"Comments"`
	Reasons   []struct {
		Type string `xml:"Type,attr"`
	} `xml:"Reasons>Reason"`
	Suggestions []struct {
		CWEID   string `xml:"CWE_ID,attr"`
		Comment string `xml:"Comment,attr"`
	} `xml:"Suggestions>Suggestion"`
}

type applicablePlatforms struct {
	Language        []applicablePlatform `xml:"Language"`
	Technology      []applicablePlatform `xml:"Technology"`
	OperatingSystem []applicablePlatform `xml:"Operating_System"`
	Architecture    []applicablePlatform `xml:"Architecture"`
}

type applicablePlatform struct {
	Class      string         `xml:"Class,attr"`
	Prevalence string         `xml:"Prevalence,attr"`
	Name       string         `xml:"Name,attr"`
	Note       structuredText `xml:"Note"`
}

type consequence struct {
	Scope      []string       `xml:"Scope"`
	Impact     []string       `xml:"Impact"`
	Note       structuredText `xml:"Note"`
	Likelihood string         `xml:"Likelihood"`
}

type observedExample struct {
	Reference   string         `xml:"Reference"`
	Description structuredText `xml:"Description"`
	Link        string         `xml:"Link"`
	Rationale   []string       `xml:"Rationale"`
}

type Weakness struct {
	ID                    string                 `json:"id,omitempty"`
	Name                  string                 `json:"name,omitempty"`
	Abstraction           string                 `json:"abstraction,omitempty"`
	Structure             string                 `json:"structure,omitempty"`
	Status                string                 `json:"status,omitempty"`
	Diagram               string                 `json:"diagram,omitempty"`
	Description           string                 `json:"description,omitempty"`
	ExtendedDescription   string                 `json:"extended_description,omitempty"`
	TechnicalNuance       string                 `json:"technical_nuance,omitempty"`
	Dimensions            []Dimension            `json:"dimensions,omitempty"`
	RelatedWeaknesses     []RelatedWeakness      `json:"related_weaknesses,omitempty"`
	ApplicablePlatforms   ApplicablePlatforms    `json:"applicable_platforms,omitzero"`
	BackgroundDetails     []string               `json:"background_details,omitempty"`
	ModesOfIntroduction   []ModesOfIntroduction  `json:"modes_of_introduction,omitempty"`
	LikelihoodOfExploit   string                 `json:"likelihood_of_exploit,omitempty"`
	CommonConsequences    []CommonConsequence    `json:"common_consequences,omitempty"`
	PotentialMitigations  []PotentialMitigation  `json:"potential_mitigations,omitempty"`
	DemonstrativeExamples []DemonstrativeExample `json:"demonstrative_examples,omitempty"`
	ObservedExamples      []ObservedExample      `json:"observed_examples,omitempty"`
	References            []Reference            `json:"references,omitempty"`
	ContentHistory        ContentHistory         `json:"content_history,omitzero"`
	WeaknessOrdinalities  []WeaknessOrdinality   `json:"weakness_ordinalities,omitempty"`
	AlternateTerms        []AlternateTerm        `json:"alternate_terms,omitempty"`
	DetectionMethods      []DetectionMethods     `json:"detection_methods,omitempty"`
	TaxonomyMappings      []TaxonomyMappings     `json:"taxonomy_mappings,omitempty"`
	RelatedAttackPatterns []string               `json:"related_attack_patterns,omitempty"`
	Notes                 []Note                 `json:"notes,omitempty"`
	AffectedResources     []string               `json:"affected_resources,omitempty"`
	FunctionalAreas       []string               `json:"functional_areas,omitempty"`
	MappingNotes          MappingNotes           `json:"mapping_notes,omitzero"`
}

type MappingNotes struct {
	Usage       string       `json:"usage,omitempty"`
	Rationale   string       `json:"rationale,omitempty"`
	Comments    string       `json:"comments,omitempty"`
	Reasons     []Reason     `json:"reasons,omitempty"`
	Suggestions []Suggestion `json:"suggestions,omitempty"`
}

type Reason struct {
	Type string `json:"type,omitempty"`
}

type Suggestion struct {
	CWEID   string `json:"cweid,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// Dimension identifies what a CWE entry, or a relationship, is based on
// (schema v8.0), e.g. Type "Behavior-Type" with "Timing".
type Dimension struct {
	Type  string `xml:"Type,attr" json:"type,omitempty"`
	Value string `xml:",chardata" json:"value,omitempty"`
}

// CustomPhase is a lifecycle phase of a domain with a lifecycle of its own
// (schema v8.0), e.g. Domain "AI" with "Training".
type CustomPhase struct {
	Domain string `xml:"Domain,attr" json:"domain,omitempty"`
	Phase  string `xml:",chardata" json:"phase,omitempty"`
}

type RelatedWeakness struct {
	Nature     string      `xml:"Nature,attr" json:"nature,omitempty"`
	CWEID      string      `xml:"CWE_ID,attr" json:"cweid,omitempty"`
	ViewID     string      `xml:"View_ID,attr" json:"view_id,omitempty"`
	Ordinal    string      `xml:"Ordinal,attr" json:"ordinal,omitempty"`
	ChainID    string      `xml:"Chain_ID,attr" json:"chain_id,omitempty"`
	Dimensions []Dimension `xml:"Dimensions>Dimension" json:"dimensions,omitempty"`
}

type ApplicablePlatforms struct {
	Language        []ApplicablePlatform `json:"language,omitempty"`
	Technology      []ApplicablePlatform `json:"technology,omitempty"`
	OperatingSystem []ApplicablePlatform `json:"operating_system,omitempty"`
	Architecture    []ApplicablePlatform `json:"architecture,omitempty"`
}

type ApplicablePlatform struct {
	Class      string `json:"class,omitempty"`
	Prevalence string `json:"prevalence,omitempty"`
	Name       string `json:"name,omitempty"`
	Note       string `json:"note,omitempty"`
}

type ModesOfIntroduction struct {
	Phase       OneOrMany[string] `json:"phase,omitempty"`
	CustomPhase []CustomPhase     `json:"custom_phase,omitempty"`
	Note        []string          `json:"note,omitempty"`
}

type CommonConsequence struct {
	Scope      []string `json:"scope,omitempty"`
	Impact     []string `json:"impact,omitempty"`
	Note       string   `json:"note,omitempty"`
	Likelihood string   `json:"likelihood,omitempty"`
}

type PotentialMitigation struct {
	MitigationID       string        `json:"mitigation_id,omitempty"`
	Phase              []string      `json:"phase,omitempty"`
	CustomPhase        []CustomPhase `json:"custom_phase,omitempty"`
	Description        []string      `json:"description,omitempty"`
	Effectiveness      string        `json:"effectiveness,omitempty"`
	EffectivenessNotes string        `json:"effectiveness_notes,omitempty"`
	Strategy           string        `json:"strategy,omitempty"`
}

type DemonstrativeExample struct {
	DemonstrativeExampleID string `xml:"Demonstrative_Example_ID,attr" json:"demonstrative_example_id,omitempty"`
	Text                   string `xml:",innerxml" json:"text,omitempty"`
}

type ObservedExample struct {
	Reference   string   `json:"reference,omitempty"`
	Description string   `json:"description,omitempty"`
	Link        string   `json:"link,omitempty"`
	Rationale   []string `json:"rationale,omitempty"`
}

type Reference struct {
	Section string `xml:"Section,attr" json:"section,omitempty"`
	ExternalReference
}

type ContentHistory struct {
	Submission        OneOrMany[Submission] `json:"submission,omitempty"`
	Modification      []Modification        `json:"modification,omitempty"`
	PreviousEntryName []PreviousEntryName   `json:"previous_entry_name,omitempty"`
	Contribution      []Contribution        `json:"contribution,omitempty"`
}

type Submission struct {
	SubmissionName         OneOrMany[string] `json:"submission_name,omitempty"`
	SubmissionOrganization string            `json:"submission_organization,omitempty"`
	SubmissionDate         string            `json:"submission_date,omitempty"`
	SubmissionVersion      string            `json:"submission_version,omitempty"`
	SubmissionReleaseDate  string            `json:"submission_release_date,omitempty"`
	SubmissionComment      string            `json:"submission_comment,omitempty"`
}

type Modification struct {
	ModificationName         string `json:"modification_name,omitempty"`
	ModificationOrganization string `json:"modification_organization,omitempty"`
	ModificationDate         string `json:"modification_date,omitempty"`
	ModificationVersion      string `json:"modification_version,omitempty"`
	ModificationReleaseDate  string `json:"modification_release_date,omitempty"`
	ModificationComment      string `json:"modification_comment,omitempty"`
	ModificationImportance   string `json:"modification_importance,omitempty"`
}

type PreviousEntryName struct {
	Text    string `json:"text,omitempty"`
	Date    string `json:"date,omitempty"`
	Version string `json:"version,omitempty"`
}

type Contribution struct {
	Type                     string            `json:"type,omitempty"`
	ContributionName         OneOrMany[string] `json:"contribution_name,omitempty"`
	ContributionOrganization string            `json:"contribution_organization,omitempty"`
	ContributionDate         string            `json:"contribution_date,omitempty"`
	ContributionVersion      string            `json:"contribution_version,omitempty"`
	ContributionReleaseDate  string            `json:"contribution_release_date,omitempty"`
	ContributionComment      string            `json:"contribution_comment,omitempty"`
}

type WeaknessOrdinality struct {
	Ordinality  string `xml:"Ordinality" json:"ordinality,omitempty"`
	Description string `xml:"Description" json:"description,omitempty"`
}

type AlternateTerm struct {
	Term        string   `json:"term,omitempty"`
	Role        []string `json:"role,omitempty"`
	Description string   `json:"description,omitempty"`
}

type DetectionMethods struct {
	DetectionMethodID  string        `json:"detection_method_id,omitempty"`
	Method             string        `json:"method,omitempty"`
	Phase              []string      `json:"phase,omitempty"`
	CustomPhase        []CustomPhase `json:"custom_phase,omitempty"`
	Description        string        `json:"description,omitempty"`
	Effectiveness      string        `json:"effectiveness,omitempty"`
	EffectivenessNotes string        `json:"effectiveness_notes,omitempty"`
}

type TaxonomyMappings struct {
	TaxonomyName string `xml:"Taxonomy_Name,attr" json:"taxonomy_name,omitempty"`
	EntryName    string `xml:"Entry_Name" json:"entry_name,omitempty"`
	EntryID      string `xml:"Entry_ID" json:"entry_id,omitempty"`
	MappingFit   string `xml:"Mapping_Fit" json:"mapping_fit,omitempty"`
}

type Note struct {
	Type        string `xml:"Type,attr" json:"type,omitempty"`
	Version     string `xml:"Version,attr" json:"version,omitempty"`
	ReleaseDate string `xml:"ReleaseDate,attr" json:"release_date,omitempty"`
	Text        string `xml:",innerxml" json:"text,omitempty"`
}

type Category struct {
	ID               string            `json:"id,omitempty"`
	Name             string            `json:"name,omitempty"`
	Status           string            `json:"status,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	ContentHistory   ContentHistory    `json:"content_history,omitzero"`
	Relationships    []HasMember       `json:"relationships,omitempty"`
	References       []Reference       `json:"references,omitempty"`
	Notes            []Note            `json:"notes,omitempty"`
	TaxonomyMappings []TaxonomyMapping `json:"taxonomy_mappings,omitempty"`
	MappingNotes     MappingNotes      `json:"mapping_notes,omitzero"`
}

type HasMember struct {
	CWEID      string      `xml:"CWE_ID,attr" json:"cweid,omitempty"`
	ViewID     string      `xml:"View_ID,attr" json:"view_id,omitempty"`
	Dimensions []Dimension `xml:"Dimensions>Dimension" json:"dimensions,omitempty"`
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
	ContentHistory ContentHistory `json:"content_history,omitzero"`
	References     []Reference    `json:"references,omitempty"`
	Filter         string         `json:"filter,omitempty"`
	MappingNotes   MappingNotes   `json:"mapping_notes,omitzero"`
}

type Audience struct {
	Type        string `xml:"Type" json:"type,omitempty"`
	Description string `xml:"Description" json:"description,omitempty"`
}

// ExternalReference is a reference of the catalog. Alt_URL, Alt_URL_Date,
// Media_Type, Access_Restrictions and Rationale are not in schema v8.0, but
// CWE 5.0 has them. Alt_URL and Alt_URL_Date pair up like URL and URL_Date.
// Media_Type and Rationale repeat, and Access_Restrictions is read as a list
// as well, since nothing states how often it may appear.
type ExternalReference struct {
	ReferenceID        string   `xml:"Reference_ID,attr" json:"reference_id,omitempty"`
	Author             []string `xml:"Author" json:"author,omitempty"`
	Title              string   `xml:"Title" json:"title,omitempty"`
	URL                string   `xml:"URL" json:"url,omitempty"`
	PublicationYear    string   `xml:"Publication_Year" json:"publication_year,omitempty"`
	PublicationMonth   string   `xml:"Publication_Month" json:"publication_month,omitempty"`
	PublicationDay     string   `xml:"Publication_Day" json:"publication_day,omitempty"`
	Publication        string   `xml:"Publication" json:"publication,omitempty"`
	Publisher          string   `xml:"Publisher" json:"publisher,omitempty"`
	Edition            string   `xml:"Edition" json:"edition,omitempty"`
	URLDate            string   `xml:"URL_Date" json:"url_date,omitempty"`
	AltURL             string   `xml:"Alt_URL" json:"alt_url,omitempty"`
	AltURLDate         string   `xml:"Alt_URL_Date" json:"alt_url_date,omitempty"`
	MediaType          []string `xml:"Media_Type" json:"media_type,omitempty"`
	AccessRestrictions []string `xml:"Access_Restrictions" json:"access_restrictions,omitempty"`
	Rationale          []string `xml:"Rationale" json:"rationale,omitempty"`
}
