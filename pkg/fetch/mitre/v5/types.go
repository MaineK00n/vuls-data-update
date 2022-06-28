package v5

type Document []struct {
	Containers struct {
		Cna struct {
			Affected []struct {
				CollectionURL   *string  `json:"collectionURL,omitempty"`
				CollectionURL2  *string  `json:"collection_url,omitempty"`
				Cpe             []string `json:"cpe,omitempty"`
				Cpes            []string `json:"cpes,omitempty"`
				DefaultStatus   *string  `json:"defaultStatus,omitempty"`
				Modules         []string `json:"modules,omitempty"`
				PackageName     *string  `json:"packageName,omitempty"`
				Platforms       []string `json:"platforms,omitempty"`
				Product         *string  `json:"product,omitempty"`
				ProgramFiles    []string `json:"programFiles,omitempty"`
				ProgramRoutines []struct {
					Name string `json:"name"`
				} `json:"programRoutines,omitempty"`
				Repo     *string `json:"repo,omitempty"`
				Vendor   *string `json:"vendor,omitempty"`
				Versions []struct {
					Changes []struct {
						At     string `json:"at"`
						Status string `json:"status"`
					} `json:"changes,omitempty"`
					GreaterThanOrEqual *string `json:"greaterThanOrEqual,omitempty"`
					LessThan           *string `json:"lessThan,omitempty"`
					LessThanOrEqual    *string `json:"lessThanOrEqual,omitempty"`
					Status             string  `json:"status"`
					Version            string  `json:"version"`
					VersionType        *string `json:"versionType,omitempty"`
				} `json:"versions,omitempty"`
				XRedhatStatus *string `json:"x_redhatStatus,omitempty"`
			} `json:"affected,omitempty"`
			Configurations []LangSupportingMediaValue `json:"configurations,omitempty"`
			Credits        []struct {
				Lang  string  `json:"lang"`
				Type  *string `json:"type,omitempty"`
				User  *string `json:"user,omitempty"`
				Value string  `json:"value"`
			} `json:"credits,omitempty"`
			DateAssigned *string                    `json:"dateAssigned,omitempty"`
			DatePublic   *string                    `json:"datePublic,omitempty"`
			Descriptions []LangSupportingMediaValue `json:"descriptions,omitempty"`
			Exploits     []LangSupportingMediaValue `json:"exploits,omitempty"`
			Impacts      []Impacts                  `json:"impacts,omitempty"`
			Metrics      []struct {
				CvssV20 *struct {
					AccessComplexity      *string `json:"accessComplexity,omitempty"`
					AccessVector          *string `json:"accessVector,omitempty"`
					Authentication        *string `json:"authentication,omitempty"`
					AvailabilityImpact    *string `json:"availabilityImpact,omitempty"`
					BaseScore             float64 `json:"baseScore"`
					ConfidentialityImpact *string `json:"confidentialityImpact,omitempty"`
					IntegrityImpact       *string `json:"integrityImpact,omitempty"`
					VectorString          string  `json:"vectorString"`
					Version               string  `json:"version"`
				} `json:"cvssV2_0,omitempty"`
				CvssV30 *struct {
					AttackComplexity      *string  `json:"attackComplexity,omitempty"`
					AttackVector          *string  `json:"attackVector,omitempty"`
					AvailabilityImpact    *string  `json:"availabilityImpact,omitempty"`
					BaseScore             float64  `json:"baseScore"`
					BaseSeverity          string   `json:"baseSeverity"`
					ConfidentialityImpact *string  `json:"confidentialityImpact,omitempty"`
					ExploitCodeMaturity   *string  `json:"exploitCodeMaturity,omitempty"`
					IntegrityImpact       *string  `json:"integrityImpact,omitempty"`
					PrivilegesRequired    *string  `json:"privilegesRequired,omitempty"`
					RemediationLevel      *string  `json:"remediationLevel,omitempty"`
					ReportConfidence      *string  `json:"reportConfidence,omitempty"`
					Scope                 *string  `json:"scope,omitempty"`
					TemporalScore         *float64 `json:"temporalScore,omitempty"`
					TemporalSeverity      *string  `json:"temporalSeverity,omitempty"`
					UserInteraction       *string  `json:"userInteraction,omitempty"`
					VectorString          string   `json:"vectorString"`
					Version               string   `json:"version"`
				} `json:"cvssV3_0,omitempty"`
				CvssV31 *struct {
					AttackComplexity              *string  `json:"attackComplexity,omitempty"`
					AttackVector                  *string  `json:"attackVector,omitempty"`
					AvailabilityImpact            *string  `json:"availabilityImpact,omitempty"`
					AvailabilityRequirement       *string  `json:"availabilityRequirement,omitempty"`
					BaseScore                     float64  `json:"baseScore"`
					BaseSeverity                  string   `json:"baseSeverity"`
					ConfidentialityImpact         *string  `json:"confidentialityImpact,omitempty"`
					ConfidentialityRequirement    *string  `json:"confidentialityRequirement,omitempty"`
					EnvironmentalScore            *float64 `json:"environmentalScore,omitempty"`
					EnvironmentalSeverity         *string  `json:"environmentalSeverity,omitempty"`
					ExploitCodeMaturity           *string  `json:"exploitCodeMaturity,omitempty"`
					IntegrityImpact               *string  `json:"integrityImpact,omitempty"`
					IntegrityRequirement          *string  `json:"integrityRequirement,omitempty"`
					ModifiedAttackComplexity      *string  `json:"modifiedAttackComplexity,omitempty"`
					ModifiedAttackVector          *string  `json:"modifiedAttackVector,omitempty"`
					ModifiedAvailabilityImpact    *string  `json:"modifiedAvailabilityImpact,omitempty"`
					ModifiedConfidentialityImpact *string  `json:"modifiedConfidentialityImpact,omitempty"`
					ModifiedIntegrityImpact       *string  `json:"modifiedIntegrityImpact,omitempty"`
					ModifiedPrivilegesRequired    *string  `json:"modifiedPrivilegesRequired,omitempty"`
					ModifiedScope                 *string  `json:"modifiedScope,omitempty"`
					ModifiedUserInteraction       *string  `json:"modifiedUserInteraction,omitempty"`
					PrivilegesRequired            *string  `json:"privilegesRequired,omitempty"`
					RemediationLevel              *string  `json:"remediationLevel,omitempty"`
					ReportConfidence              *string  `json:"reportConfidence,omitempty"`
					Scope                         *string  `json:"scope,omitempty"`
					TemporalScore                 *float64 `json:"temporalScore,omitempty"`
					TemporalSeverity              *string  `json:"temporalSeverity,omitempty"`
					UserInteraction               *string  `json:"userInteraction,omitempty"`
					VectorString                  string   `json:"vectorString"`
					Version                       string   `json:"version"`
				} `json:"cvssV3_1,omitempty"`
				Format *string `json:"format,omitempty"`
				Other  *struct {
					Content struct {
						AttackComplexity      *string      `json:"attackComplexity,omitempty"`
						AttackVector          *string      `json:"attackVector,omitempty"`
						Automatable           *string      `json:"Automatable,omitempty"`
						AvailabilityImpact    *string      `json:"availabilityImpact,omitempty"`
						BaseScore             *float64     `json:"baseScore,omitempty"`
						BaseSeverity          *string      `json:"baseSeverity,omitempty"`
						ConfidentialityImpact *string      `json:"confidentialityImpact,omitempty"`
						Description           *Description `json:"description,omitempty"`
						Exploitation          *string      `json:"Exploitation,omitempty"`
						IntegrityImpact       *string      `json:"integrityImpact,omitempty"`
						Lang                  *string      `json:"lang,omitempty"`
						Namespace             *string      `json:"namespace,omitempty"`
						Other                 *string      `json:"other,omitempty"`
						PrivilegesRequired    *string      `json:"privilegesRequired,omitempty"`
						Scope                 *string      `json:"scope,omitempty"`
						Ssvc                  *string      `json:"ssvc,omitempty"`
						TechnicalImpact       *string      `json:"Technical Impact,omitempty"`
						Text                  *string      `json:"text,omitempty"`
						URL                   *string      `json:"url,omitempty"`
						UserInteraction       *string      `json:"userInteraction,omitempty"`
						Value                 *string      `json:"value,omitempty"`
						ValueDensity          *string      `json:"Value Density,omitempty"`
						VectorString          *string      `json:"vectorString,omitempty"`
						Version               interface{}  `json:"version,omitempty"`
					} `json:"content"`
					Type    string  `json:"type"`
					Version *string `json:"version,omitempty"`
				} `json:"other,omitempty"`
				Scenario  *string     `json:"scenario,omitempty"`
				Scenarios []LangValue `json:"scenarios,omitempty"`
			} `json:"metrics,omitempty"`
			ProblemTypes []struct {
				Descriptions []struct {
					CWEID       *string    `json:"CWE-ID,omitempty"`
					CweID       *string    `json:"cweId,omitempty"`
					Cweid       *string    `json:"cweid,omitempty"`
					Description string     `json:"description"`
					Lang        string     `json:"lang"`
					Reference   *Reference `json:"reference,omitempty"`
					Type        *string    `json:"type,omitempty"`
				} `json:"descriptions"`
			} `json:"problemTypes,omitempty"`
			ProviderMetadata struct {
				DateUpdated *string `json:"dateUpdated,omitempty"`
				OrgID       string  `json:"orgId"`
				ShortName   *string `json:"shortName,omitempty"`
			} `json:"providerMetadata"`
			References []struct {
				Name      *string  `json:"name,omitempty"`
				Refsource *string  `json:"refsource,omitempty"`
				Tags      []string `json:"tags,omitempty"`
				URL       string   `json:"url"`
			} `json:"references,omitempty"`
			RejectedReasons []LangSupportingMediaValue `json:"rejectedReasons,omitempty"`
			ReplacedBy      []string                   `json:"replacedBy,omitempty"`
			Solutions       []LangSupportingMediaValue `json:"solutions,omitempty"`
			Source          *struct {
				Advisory    *string     `json:"advisory,omitempty"`
				Defect      interface{} `json:"defect,omitempty"`
				Defects     []string    `json:"defects,omitempty"`
				Discovery   *string     `json:"discovery,omitempty"`
				FoundDuring *string     `json:"found_during,omitempty"`
				Lang        *string     `json:"lang,omitempty"`
				Value       *string     `json:"value,omitempty"`
			} `json:"source,omitempty"`
			Tags             []string `json:"tags,omitempty"`
			TaxonomyMappings []struct {
				TaxonomyName      string `json:"taxonomyName"`
				TaxonomyRelations []struct {
					RelationshipName  string `json:"relationshipName"`
					RelationshipValue string `json:"relationshipValue"`
					TaxonomyID        string `json:"taxonomyId"`
				} `json:"taxonomyRelations"`
				TaxonomyVersion string `json:"taxonomyVersion"`
			} `json:"taxonomyMappings,omitempty"`
			Timeline         []Timeline                 `json:"timeline,omitempty"`
			Title            *string                    `json:"title,omitempty"`
			Workarounds      []LangSupportingMediaValue `json:"workarounds,omitempty"`
			XConverterErrors map[string]struct {
				Error   string `json:"error"`
				Message string `json:"message"`
			} `json:"x_ConverterErrors,omitempty"`
			XGenerator      interface{} `json:"x_generator,omitempty"`
			XLegacyV4Record *struct {
				Affects *struct {
					Vendor struct {
						VendorData []struct {
							Product struct {
								ProductData []struct {
									ProductName string `json:"product_name"`
									Version     struct {
										VersionData []map[string]string `json:"version_data"`
									} `json:"version"`
								} `json:"product_data"`
							} `json:"product"`
							VendorName string `json:"vendor_name"`
						} `json:"vendor_data"`
					} `json:"vendor"`
				} `json:"affects,omitempty"`
				CNAPrivate *struct {
					InternalComments string `json:"internal_comments"`
					Owner            string `json:"owner"`
					Publish          struct {
						Month string `json:"month"`
						Year  string `json:"year"`
						Ym    string `json:"ym"`
					} `json:"publish"`
					ShareWithCVE bool `json:"share_with_CVE"`
				} `json:"CNA_private,omitempty"`
				CVEDataMeta   map[string]string `json:"CVE_data_meta"`
				Configuration interface{}       `json:"configuration,omitempty"`
				Containers    *struct {
					Cna struct {
						Affected []struct {
							DefaultStatus string `json:"defaultStatus"`
							Product       string `json:"product"`
							Vendor        string `json:"vendor"`
							Versions      []struct {
								LessThanOrEqual string `json:"lessThanOrEqual"`
								Status          string `json:"status"`
								Version         string `json:"version"`
								VersionType     string `json:"versionType"`
							} `json:"versions"`
						} `json:"affected"`
						Descriptions []LangSupportingMediaValue `json:"descriptions"`
						Impacts      []Impacts                  `json:"impacts"`
						Metrics      []struct {
							CvssV31 struct {
								AttackComplexity      string  `json:"attackComplexity"`
								AttackVector          string  `json:"attackVector"`
								AvailabilityImpact    string  `json:"availabilityImpact"`
								BaseScore             float64 `json:"baseScore"`
								BaseSeverity          string  `json:"baseSeverity"`
								ConfidentialityImpact string  `json:"confidentialityImpact"`
								IntegrityImpact       string  `json:"integrityImpact"`
								PrivilegesRequired    string  `json:"privilegesRequired"`
								Scope                 string  `json:"scope"`
								UserInteraction       string  `json:"userInteraction"`
								VectorString          string  `json:"vectorString"`
								Version               string  `json:"version"`
							} `json:"cvssV3_1"`
							Format    string      `json:"format"`
							Scenarios []LangValue `json:"scenarios"`
						} `json:"metrics"`
						ProblemTypes []struct {
							Descriptions []struct {
								CweID       string `json:"cweId"`
								Description string `json:"description"`
								Lang        string `json:"lang"`
								Type        string `json:"type"`
							} `json:"descriptions"`
						} `json:"problemTypes"`
						ProviderMetadata struct {
							OrgID string `json:"orgId"`
						} `json:"providerMetadata"`
						References []Reference `json:"references"`
						Source     struct {
							Discovery string `json:"discovery"`
						} `json:"source"`
						Title      string `json:"title"`
						XGenerator struct {
							Engine string `json:"engine"`
						} `json:"x_generator"`
					} `json:"cna"`
				} `json:"containers,omitempty"`
				Credit      interface{} `json:"credit,omitempty"`
				CveID       *string     `json:"cve_id,omitempty"`
				CveMetadata *struct {
					AssignerOrgID   string `json:"assignerOrgId"`
					CveID           string `json:"cveId"`
					RequesterUserID string `json:"requesterUserId"`
					Serial          int    `json:"serial"`
					State           string `json:"state"`
				} `json:"cveMetadata,omitempty"`
				DataFormat   string      `json:"data_format"`
				DataType     string      `json:"data_type"`
				DataType2    *string     `json:"dataType,omitempty"`
				DataVersion  string      `json:"data_version"`
				DataVersion2 *string     `json:"dataVersion,omitempty"`
				Description  Description `json:"description"`
				Discoverer   *string     `json:"discoverer,omitempty"`
				Exploit      interface{} `json:"exploit,omitempty"`
				Generator    interface{} `json:"generator,omitempty"`
				Impact       interface{} `json:"impact,omitempty"`
				Problemtype  *struct {
					ProblemtypeData []Description2 `json:"problemtype_data"`
				} `json:"problemtype,omitempty"`
				References struct {
					ReferenceData []struct {
						Name      *string `json:"name,omitempty"`
						Refsource *string `json:"refsource,omitempty"`
						Title     *string `json:"title,omitempty"`
						URL       string  `json:"url"`
					} `json:"reference_data"`
				} `json:"references"`
				Solution interface{} `json:"solution,omitempty"`
				Source   *struct {
					Advisory    *string     `json:"advisory,omitempty"`
					Defect      interface{} `json:"defect,omitempty"`
					Discovery   *string     `json:"discovery,omitempty"`
					FoundDuring *string     `json:"found_during,omitempty"`
				} `json:"source,omitempty"`
				Timeline   []Timeline  `json:"timeline,omitempty"`
				WorkAround []LangValue `json:"work_around,omitempty"`
				Workaround *struct {
					WorkaroundData Description2 `json:"workaround_data"`
				} `json:"workaround,omitempty"`
				XAdvisoryEoL        *bool    `json:"x_advisoryEoL,omitempty"`
				XAffectedList       []string `json:"x_affectedList,omitempty"`
				XLikelyAffectedList []string `json:"x_likelyAffectedList,omitempty"`
			} `json:"x_legacyV4Record,omitempty"`
			XRedHatCweChain *string `json:"x_redHatCweChain,omitempty"`
			XRedhatCweChain *string `json:"x_redhatCweChain,omitempty"`
		} `json:"cna"`
	} `json:"containers"`
	CveMetadata struct {
		AssignerOrgID     string  `json:"assignerOrgId"`
		AssignerShortName *string `json:"assignerShortName,omitempty"`
		CveID             string  `json:"cveId"`
		DatePublished     *string `json:"datePublished,omitempty"`
		DateRejected      *string `json:"dateRejected,omitempty"`
		DateReserved      string  `json:"dateReserved"`
		DateUpdated       *string `json:"dateUpdated,omitempty"`
		RequesterUserID   *string `json:"requesterUserId,omitempty"`
		Serial            *int    `json:"serial,omitempty"`
		State             string  `json:"state"`
	} `json:"cveMetadata"`
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
}
type LangValue struct {
	Lang  string  `json:"lang"`
	Value *string `json:"value,omitempty"`
}
type Description struct {
	DescriptionData []LangValue `json:"description_data"`
}
type Impacts struct {
	CapecID      *string     `json:"capecId,omitempty"`
	Descriptions []LangValue `json:"descriptions"`
}
type Description2 struct {
	Description []LangValue `json:"description"`
}
type Reference struct {
	URL string `json:"url"`
}
type SupportingMedia struct {
	Base64 bool   `json:"base64"`
	Type   string `json:"type"`
	Value  string `json:"value"`
}
type LangSupportingMediaValue struct {
	Lang            string            `json:"lang"`
	SupportingMedia []SupportingMedia `json:"supportingMedia,omitempty"`
	Value           string            `json:"value"`
}
type Timeline struct {
	Lang  string  `json:"lang"`
	Time  *string `json:"time,omitempty"`
	Value *string `json:"value,omitempty"`
}

package main

type T []struct {
	Containers struct {
		Cna struct {
			Affected []struct {
				CollectionURL   string   `json:"collectionURL,omitempty"`
				CollectionURL   string   `json:"collection_url,omitempty"`
				Cpe             []string `json:"cpe,omitempty"`
				Cpes            []string `json:"cpes"`
				DefaultStatus   string   `json:"defaultStatus,omitempty"`
				Modules         []string `json:"modules,omitempty"`
				PackageName     string   `json:"packageName,omitempty"`
				Platforms       []string `json:"platforms,omitempty"`
				Product         string   `json:"product,omitempty"`
				ProgramFiles    []string `json:"programFiles,omitempty"`
				ProgramRoutines []struct {
					Name string `json:"name"`
				} `json:"programRoutines,omitempty"`
				Repo     string `json:"repo,omitempty"`
				Vendor   string `json:"vendor,omitempty"`
				Versions []struct {
					Changes []struct {
						At     string `json:"at"`
						Status string `json:"status"`
					} `json:"changes,omitempty"`
					GreaterThanOrEqual string `json:"greaterThanOrEqual,omitempty"`
					LessThan           string `json:"lessThan,omitempty"`
					LessThanOrEqual    string `json:"lessThanOrEqual,omitempty"`
					Status             string `json:"status"`
					Version            string `json:"version"`
					VersionType        string `json:"versionType,omitempty"`
				} `json:"versions,omitempty"`
				XRedhatStatus string `json:"x_redhatStatus,omitempty"`
			} `json:"affected,omitempty"`
			Configurations []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"configurations,omitempty"`
			Credits []struct {
				Lang  string `json:"lang"`
				Type  string `json:"type,omitempty"`
				User  string `json:"user,omitempty"`
				Value string `json:"value"`
			} `json:"credits,omitempty"`
			DateAssigned string `json:"dateAssigned,omitempty"`
			DatePublic   string `json:"datePublic,omitempty"`
			Descriptions []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"descriptions,omitempty"`
			Exploits []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"exploits,omitempty"`
			Impacts []struct {
				CapecID      string `json:"capecId,omitempty"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"impacts,omitempty"`
			Metrics []struct {
				CvssV20 *struct {
					AccessComplexity      string  `json:"accessComplexity,omitempty"`
					AccessVector          string  `json:"accessVector,omitempty"`
					Authentication        string  `json:"authentication,omitempty"`
					AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
					BaseScore             float64 `json:"baseScore"`
					ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
					IntegrityImpact       string  `json:"integrityImpact,omitempty"`
					VectorString          string  `json:"vectorString"`
					Version               string  `json:"version"`
				} `json:"cvssV2_0,omitempty"`
				CvssV30 *struct {
					AttackComplexity      string  `json:"attackComplexity,omitempty"`
					AttackVector          string  `json:"attackVector,omitempty"`
					AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
					BaseScore             float64 `json:"baseScore"`
					BaseSeverity          string  `json:"baseSeverity"`
					ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
					ExploitCodeMaturity   string  `json:"exploitCodeMaturity,omitempty"`
					IntegrityImpact       string  `json:"integrityImpact,omitempty"`
					PrivilegesRequired    string  `json:"privilegesRequired,omitempty"`
					RemediationLevel      string  `json:"remediationLevel,omitempty"`
					ReportConfidence      string  `json:"reportConfidence,omitempty"`
					Scope                 string  `json:"scope,omitempty"`
					TemporalScore         float64 `json:"temporalScore,omitempty"`
					TemporalSeverity      string  `json:"temporalSeverity,omitempty"`
					UserInteraction       string  `json:"userInteraction,omitempty"`
					VectorString          string  `json:"vectorString"`
					Version               string  `json:"version"`
				} `json:"cvssV3_0,omitempty"`
				CvssV31 *struct {
					AttackComplexity              string  `json:"attackComplexity,omitempty"`
					AttackVector                  string  `json:"attackVector,omitempty"`
					AvailabilityImpact            string  `json:"availabilityImpact,omitempty"`
					AvailabilityRequirement       string  `json:"availabilityRequirement,omitempty"`
					BaseScore                     float64 `json:"baseScore"`
					BaseSeverity                  string  `json:"baseSeverity"`
					ConfidentialityImpact         string  `json:"confidentialityImpact,omitempty"`
					ConfidentialityRequirement    string  `json:"confidentialityRequirement,omitempty"`
					EnvironmentalScore            float64 `json:"environmentalScore,omitempty"`
					EnvironmentalSeverity         string  `json:"environmentalSeverity,omitempty"`
					ExploitCodeMaturity           string  `json:"exploitCodeMaturity,omitempty"`
					IntegrityImpact               string  `json:"integrityImpact,omitempty"`
					IntegrityRequirement          string  `json:"integrityRequirement,omitempty"`
					ModifiedAttackComplexity      string  `json:"modifiedAttackComplexity,omitempty"`
					ModifiedAttackVector          string  `json:"modifiedAttackVector,omitempty"`
					ModifiedAvailabilityImpact    string  `json:"modifiedAvailabilityImpact,omitempty"`
					ModifiedConfidentialityImpact string  `json:"modifiedConfidentialityImpact,omitempty"`
					ModifiedIntegrityImpact       string  `json:"modifiedIntegrityImpact,omitempty"`
					ModifiedPrivilegesRequired    string  `json:"modifiedPrivilegesRequired,omitempty"`
					ModifiedScope                 string  `json:"modifiedScope,omitempty"`
					ModifiedUserInteraction       string  `json:"modifiedUserInteraction,omitempty"`
					PrivilegesRequired            string  `json:"privilegesRequired,omitempty"`
					RemediationLevel              string  `json:"remediationLevel,omitempty"`
					ReportConfidence              string  `json:"reportConfidence,omitempty"`
					Scope                         string  `json:"scope,omitempty"`
					TemporalScore                 float64 `json:"temporalScore,omitempty"`
					TemporalSeverity              string  `json:"temporalSeverity,omitempty"`
					UserInteraction               string  `json:"userInteraction,omitempty"`
					VectorString                  string  `json:"vectorString"`
					Version                       string  `json:"version"`
				} `json:"cvssV3_1,omitempty"`
				Format string `json:"format,omitempty"`
				Other  *struct {
					Content struct {
						Automatable           string  `json:"Automatable,omitempty"`
						Exploitation          string  `json:"Exploitation,omitempty"`
						AttackComplexity      string  `json:"attackComplexity,omitempty"`
						AttackVector          string  `json:"attackVector,omitempty"`
						AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
						BaseScore             float64 `json:"baseScore,omitempty"`
						BaseSeverity          string  `json:"baseSeverity,omitempty"`
						ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
						Description           *struct {
							DescriptionData []struct {
								Lang  string `json:"lang"`
								Value string `json:"value"`
							} `json:"description_data"`
						} `json:"description,omitempty"`
						IntegrityImpact    string      `json:"integrityImpact,omitempty"`
						Lang               string      `json:"lang,omitempty"`
						Namespace          string      `json:"namespace,omitempty"`
						Other              string      `json:"other,omitempty"`
						PrivilegesRequired string      `json:"privilegesRequired,omitempty"`
						Scope              string      `json:"scope,omitempty"`
						Ssvc               string      `json:"ssvc,omitempty"`
						Text               string      `json:"text,omitempty"`
						URL                string      `json:"url,omitempty"`
						UserInteraction    string      `json:"userInteraction,omitempty"`
						Value              string      `json:"value,omitempty"`
						VectorString       string      `json:"vectorString,omitempty"`
						Version            interface{} `json:"version,omitempty"`
						// "Technical Impact" cannot be unmarshalled into a struct field by encoding/json.
						// "Value Density" cannot be unmarshalled into a struct field by encoding/json.
					} `json:"content"`
					Type    string `json:"type"`
					Version string `json:"version,omitempty"`
				} `json:"other,omitempty"`
				Scenario  string `json:"scenario,omitempty"`
				Scenarios []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"scenarios,omitempty"`
			} `json:"metrics,omitempty"`
			ProblemTypes []struct {
				Descriptions []struct {
					CweID       string `json:"CWE-ID,omitempty"`
					CweID       string `json:"cweId,omitempty"`
					Cweid       string `json:"cweid,omitempty"`
					Description string `json:"description"`
					Lang        string `json:"lang"`
					Reference   *struct {
						URL string `json:"url"`
					} `json:"reference,omitempty"`
					Type string `json:"type,omitempty"`
				} `json:"descriptions"`
			} `json:"problemTypes,omitempty"`
			ProviderMetadata struct {
				DateUpdated string `json:"dateUpdated,omitempty"`
				OrgID       string `json:"orgId"`
				ShortName   string `json:"shortName,omitempty"`
			} `json:"providerMetadata"`
			References []struct {
				Name      string   `json:"name,omitempty"`
				Refsource string   `json:"refsource,omitempty"`
				Tags      []string `json:"tags,omitempty"`
				URL       string   `json:"url"`
			} `json:"references,omitempty"`
			RejectedReasons []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"rejectedReasons,omitempty"`
			ReplacedBy []string `json:"replacedBy,omitempty"`
			Solutions  []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"solutions,omitempty"`
			Source *struct {
				Advisory    string        `json:"advisory"`
				Defect      []interface{} `json:"defect"`
				Defects     []string      `json:"defects,omitempty"`
				Discovery   string        `json:"discovery"`
				FoundDuring string        `json:"found_during,omitempty"`
				Lang        string        `json:"lang,omitempty"`
				Value       string        `json:"value,omitempty"`
			} `json:"source,omitempty"`
			Tags             []string `json:"tags,omitempty"`
			TaxonomyMappings []struct {
				TaxonomyName      string `json:"taxonomyName"`
				TaxonomyRelations []struct {
					RelationshipName  string `json:"relationshipName"`
					RelationshipValue string `json:"relationshipValue"`
					TaxonomyID        string `json:"taxonomyId"`
				} `json:"taxonomyRelations"`
				TaxonomyVersion string `json:"taxonomyVersion"`
			} `json:"taxonomyMappings,omitempty"`
			Timeline []struct {
				Lang  string `json:"lang"`
				Time  string `json:"time"`
				Value string `json:"value"`
			} `json:"timeline,omitempty"`
			Title       string `json:"title,omitempty"`
			Workarounds []struct {
				Lang            string `json:"lang"`
				SupportingMedia []struct {
					Base64 bool   `json:"base64"`
					Type   string `json:"type"`
					Value  string `json:"value"`
				} `json:"supportingMedia,omitempty"`
				Value string `json:"value"`
			} `json:"workarounds,omitempty"`
			XConverterErrors *struct {
				DatePublic *struct {
					Error   string `json:"error"`
					Message string `json:"message"`
				} `json:"DATE_PUBLIC,omitempty"`
				Title *struct {
					Error   string `json:"error"`
					Message string `json:"message"`
				} `json:"TITLE,omitempty"`
				Affects *struct {
					Error   string `json:"error"`
					Message string `json:"message"`
				} `json:"affects,omitempty"`
				CvssV30 *struct {
					Error   string `json:"error"`
					Message string `json:"message"`
				} `json:"cvssV3_0,omitempty"`
				CvssV31 *struct {
					Error   string `json:"error"`
					Message string `json:"message"`
				} `json:"cvssV3_1,omitempty"`
				ProductName *struct {
					Error   string `json:"error"`
					Message string `json:"message"`
				} `json:"product_name,omitempty"`
				VersionName *struct {
					Error   string `json:"error"`
					Message string `json:"message"`
				} `json:"version_name,omitempty"`
			} `json:"x_ConverterErrors,omitempty"`
			XGenerator      interface{} `json:"x_generator,omitempty"`
			XLegacyV4Record *struct {
				CnaPrivate *struct {
					CveList             []interface{} `json:"CVE_list"`
					CveTableDescription []interface{} `json:"CVE_table_description"`
					InternalComments    string        `json:"internal_comments"`
					Owner               string        `json:"owner"`
					Publish             struct {
						Month string `json:"month"`
						Year  string `json:"year"`
						Ym    string `json:"ym"`
					} `json:"publish"`
					ShareWithCve bool          `json:"share_with_CVE"`
					Todo         []interface{} `json:"todo"`
				} `json:"CNA_private,omitempty"`
				CveDataMeta struct {
					Aka           string `json:"AKA"`
					Assigner      string `json:"ASSIGNER"`
					DataAssigned  string `json:"DATA_ASSIGNED,omitempty"`
					DateAssigned  string `json:"DATE_ASSIGNED,omitempty"`
					DateAssignede string `json:"DATE_ASSIGNEDE,omitempty"`
					DatePublic    string `json:"DATE_PUBLIC"`
					DateRequested string `json:"DATE_REQUESTED,omitempty"`
					ID            string `json:"ID"`
					Requester     string `json:"REQUESTER,omitempty"`
					State         string `json:"STATE"`
					StateDetail   string `json:"STATE_DETAIL,omitempty"`
					Title         string `json:"TITLE"`
					Updated       string `json:"UPDATED,omitempty"`
					VendorName    string `json:"vendor_name,omitempty"`
				} `json:"CVE_data_meta"`
				Affects *struct {
					Vendor struct {
						VendorData []struct {
							Product struct {
								ProductData []struct {
									ProductName string `json:"product_name"`
									Version     struct {
										VersionData []struct {
											Affected         string `json:"affected,omitempty"`
											Affected_        string `json:"affected:,omitempty"`
											Configuration    string `json:"configuration,omitempty"`
											Platform         string `json:"platform"`
											VersionAffected  string `json:"version_affected"`
											VersionBegin     string `json:"version_begin,omitempty"`
											VersionName      string `json:"version_name"`
											VersionNumber    string `json:"version_number,omitempty"`
											VersionValue     string `json:"version_value"`
											VersionsAffected string `json:"versions_affected,omitempty"`
										} `json:"version_data"`
									} `json:"version"`
								} `json:"product_data"`
							} `json:"product"`
							VendorName string `json:"vendor_name"`
						} `json:"vendor_data"`
					} `json:"vendor"`
				} `json:"affects,omitempty"`
				Configuration interface{} `json:"configuration,omitempty"`
				Containers    *struct {
					Cna struct {
						Affected []struct {
							DefaultStatus string `json:"defaultStatus"`
							Product       string `json:"product"`
							Vendor        string `json:"vendor"`
							Versions      []struct {
								LessThanOrEqual string `json:"lessThanOrEqual"`
								Status          string `json:"status"`
								Version         string `json:"version"`
								VersionType     string `json:"versionType"`
							} `json:"versions"`
						} `json:"affected"`
						Descriptions []struct {
							Lang            string `json:"lang"`
							SupportingMedia []struct {
								Base64 bool   `json:"base64"`
								Type   string `json:"type"`
								Value  string `json:"value"`
							} `json:"supportingMedia"`
							Value string `json:"value"`
						} `json:"descriptions"`
						Impacts []struct {
							CapecID      string `json:"capecId"`
							Descriptions []struct {
								Lang  string `json:"lang"`
								Value string `json:"value"`
							} `json:"descriptions"`
						} `json:"impacts"`
						Metrics []struct {
							CvssV31 struct {
								AttackComplexity      string  `json:"attackComplexity"`
								AttackVector          string  `json:"attackVector"`
								AvailabilityImpact    string  `json:"availabilityImpact"`
								BaseScore             float64 `json:"baseScore"`
								BaseSeverity          string  `json:"baseSeverity"`
								ConfidentialityImpact string  `json:"confidentialityImpact"`
								IntegrityImpact       string  `json:"integrityImpact"`
								PrivilegesRequired    string  `json:"privilegesRequired"`
								Scope                 string  `json:"scope"`
								UserInteraction       string  `json:"userInteraction"`
								VectorString          string  `json:"vectorString"`
								Version               string  `json:"version"`
							} `json:"cvssV3_1"`
							Format    string `json:"format"`
							Scenarios []struct {
								Lang  string `json:"lang"`
								Value string `json:"value"`
							} `json:"scenarios"`
						} `json:"metrics"`
						ProblemTypes []struct {
							Descriptions []struct {
								CweID       string `json:"cweId"`
								Description string `json:"description"`
								Lang        string `json:"lang"`
								Type        string `json:"type"`
							} `json:"descriptions"`
						} `json:"problemTypes"`
						ProviderMetadata struct {
							OrgID string `json:"orgId"`
						} `json:"providerMetadata"`
						References []struct {
							URL string `json:"url"`
						} `json:"references"`
						Source struct {
							Discovery string `json:"discovery"`
						} `json:"source"`
						Title      string `json:"title"`
						XGenerator struct {
							Engine string `json:"engine"`
						} `json:"x_generator"`
					} `json:"cna"`
				} `json:"containers,omitempty"`
				Credit      interface{} `json:"credit,omitempty"`
				CveMetadata *struct {
					AssignerOrgID   string `json:"assignerOrgId"`
					CveID           string `json:"cveId"`
					RequesterUserID string `json:"requesterUserId"`
					Serial          int    `json:"serial"`
					State           string `json:"state"`
				} `json:"cveMetadata,omitempty"`
				CveID       string `json:"cve_id,omitempty"`
				DataType    string `json:"dataType,omitempty"`
				DataVersion string `json:"dataVersion,omitempty"`
				DataFormat  string `json:"data_format"`
				DataType    string `json:"data_type"`
				DataVersion string `json:"data_version"`
				Description struct {
					DescriptionData []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
				Discoverer  string      `json:"discoverer,omitempty"`
				Exploit     interface{} `json:"exploit,omitempty"`
				Generator   interface{} `json:"generator,omitempty"`
				Impact      interface{} `json:"impact,omitempty"`
				Problemtype *struct {
					ProblemtypeData []struct {
						Description []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						} `json:"description"`
					} `json:"problemtype_data"`
				} `json:"problemtype,omitempty"`
				References struct {
					ReferenceData []struct {
						Name      string `json:"name"`
						Refsource string `json:"refsource,omitempty"`
						Title     string `json:"title,omitempty"`
						URL       string `json:"url"`
					} `json:"reference_data"`
				} `json:"references"`
				Solution interface{} `json:"solution,omitempty"`
				Source   *struct {
					Advisory    string        `json:"advisory"`
					Defect      []interface{} `json:"defect"`
					Discovery   string        `json:"discovery"`
					FoundDuring string        `json:"found_during,omitempty"`
				} `json:"source,omitempty"`
				Timeline []struct {
					Lang  string `json:"lang"`
					Time  string `json:"time,omitempty"`
					Value string `json:"value,omitempty"`
				} `json:"timeline,omitempty"`
				WorkAround []struct {
					Lang  string `json:"lang"`
					Value string `json:"value,omitempty"`
				} `json:"work_around"`
				Workaround *struct {
					WorkaroundData struct {
						Description struct {
							DescriptionData []struct {
								Lang  string `json:"lang"`
								Value string `json:"value"`
							} `json:"description_data"`
						} `json:"description"`
					} `json:"workaround_data"`
				} `json:"workaround,omitempty"`
				XAdvisoryEoL        bool     `json:"x_advisoryEoL"`
				XAffectedList       []string `json:"x_affectedList,omitempty"`
				XLikelyAffectedList []string `json:"x_likelyAffectedList,omitempty"`
			} `json:"x_legacyV4Record,omitempty"`
			XRedHatCweChain string `json:"x_redHatCweChain,omitempty"`
			XRedhatCweChain string `json:"x_redhatCweChain,omitempty"`
		} `json:"cna"`
	} `json:"containers"`
	CveMetadata struct {
		AssignerOrgID     string `json:"assignerOrgId"`
		AssignerShortName string `json:"assignerShortName,omitempty"`
		CveID             string `json:"cveId"`
		DatePublished     string `json:"datePublished,omitempty"`
		DateRejected      string `json:"dateRejected,omitempty"`
		DateReserved      string `json:"dateReserved"`
		DateUpdated       string `json:"dateUpdated,omitempty"`
		RequesterUserID   string `json:"requesterUserId,omitempty"`
		Serial            int    `json:"serial,omitempty"`
		State             string `json:"state"`
	} `json:"cveMetadata"`
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
}
