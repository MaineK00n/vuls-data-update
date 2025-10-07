package wsusscn2

type index struct {
	CABLIST struct {
		CAB []cab `xml:"CAB"`
	} `xml:"CABLIST"`
}

type cab struct {
	NAME       string `xml:"NAME,attr"`
	RANGESTART string `xml:"RANGESTART,attr"`
}

type offlineSyncPackage struct {
	MinimumClientVersion string `xml:"MinimumClientVersion,attr" json:"minimumclientversion,omitempty"`
	PackageId            string `xml:"PackageId,attr" json:"packageid,omitempty"`
	PackageVersion       string `xml:"PackageVersion,attr" json:"packageversion,omitempty"`
	ProtocolVersion      string `xml:"ProtocolVersion,attr" json:"protocolversion,omitempty"`
	CreationDate         string `xml:"CreationDate,attr" json:"creationdate,omitempty"`
	SourceId             string `xml:"SourceId,attr" json:"sourceid,omitempty"`
	Updates              struct {
		Update []Update `xml:"Update" json:"update,omitempty"`
	} `xml:"Updates" json:"updates,omitempty"`
	FileLocations struct {
		FileLocation []struct {
			ID         string `xml:"Id,attr" json:"id,omitempty"`
			URL        string `xml:"Url,attr" json:"url,omitempty"`
			IsIncluded string `xml:"IsIncluded,attr" json:"isincluded,omitempty"`
		} `xml:"FileLocation" json:"filelocation,omitempty"`
	} `xml:"FileLocations" json:"filelocations,omitempty"`
}

type Update struct {
	CreationDate    string `xml:"CreationDate,attr" json:"creationdate,omitempty"`
	DefaultLanguage string `xml:"DefaultLanguage,attr" json:"defaultlanguage,omitempty"`
	UpdateID        string `xml:"UpdateId,attr" json:"updateid,omitempty"`
	// RevisionNumber   string `xml:"RevisionNumber,attr" json:"revisionnumber,omitempty"`
	RevisionID       string `xml:"RevisionId,attr" json:"revisionid,omitempty"`
	IsLeaf           string `xml:"IsLeaf,attr" json:"isleaf,omitempty"`
	IsBundle         string `xml:"IsBundle,attr" json:"isbundle,omitempty"`
	DeploymentAction string `xml:"DeploymentAction,attr" json:"deploymentaction,omitempty"`
	IsSoftware       string `xml:"IsSoftware,attr" json:"issoftware,omitempty"`
	// Prerequisites    struct {
	// 	UpdateId []struct {
	// 		ID string `xml:"Id,attr" json:"id,omitempty"`
	// 	} `xml:"UpdateId" json:"updateid,omitempty"`
	// 	Or []struct {
	// 		UpdateId []struct {
	// 			ID string `xml:"Id,attr" json:"id,omitempty"`
	// 		} `xml:"UpdateId" json:"updateid,omitempty"`
	// 	} `xml:"Or" json:"or,omitempty"`
	// } `xml:"Prerequisites" json:"prerequisites,omitempty"`
	Categories struct {
		Category []struct {
			Type string `xml:"Type,attr" json:"type,omitempty"`
			ID   string `xml:"Id,attr" json:"id,omitempty"`
		} `xml:"Category" json:"category,omitempty"`
	} `xml:"Categories" json:"categories,omitempty"`
	// PayloadFiles struct {
	// 	File []struct {
	// 		ID string `xml:"Id,attr" json:"id,omitempty"`
	// 	} `xml:"File" json:"file,omitempty"`
	// } `xml:"PayloadFiles" json:"payloadfiles,omitempty"`
	Languages struct {
		Language []struct {
			Name string `xml:"Name,attr" json:"name,omitempty"`
		} `xml:"Language" json:"language,omitempty"`
	} `xml:"Languages" json:"languages,omitempty"`
	// BundledBy struct {
	// 	Revision []struct {
	// 		ID string `xml:"Id,attr" json:"id,omitempty"`
	// 	} `xml:"Revision" json:"revision,omitempty"`
	// } `xml:"BundledBy" json:"bundledby,omitempty"`
	SupersededBy struct {
		Revision []struct {
			ID string `xml:"Id,attr" json:"id,omitempty"`
		} `xml:"Revision" json:"revision,omitempty"`
	} `xml:"SupersededBy" json:"supersededby,omitempty"`
	// EulaFiles struct {
	// 	File []struct {
	// 		ID       string `xml:"Id,attr" json:"id,omitempty"`
	// 		Language struct {
	// 			Name string `xml:"Name,attr" json:"name,omitempty"`
	// 		} `xml:"Language" json:"language,omitempty"`
	// 	} `xml:"File" json:"file,omitempty"`
	// } `xml:"EulaFiles" json:"eulafiles,omitempty"`
}

type X struct {
	DefaultPropertiesLanguage  string `xml:"DefaultPropertiesLanguage,attr" json:"defaultpropertieslanguage,omitempty"`
	Handler                    string `xml:"Handler,attr" json:"handler,omitempty"`
	MaxDownloadSize            string `xml:"MaxDownloadSize,attr" json:"maxdownloadsize,omitempty"`
	MinDownloadSize            string `xml:"MinDownloadSize,attr" json:"mindownloadsize,omitempty"`
	MsrcSeverity               string `xml:"MsrcSeverity,attr" json:"msrcseverity,omitempty"`
	IsBeta                     string `xml:"IsBeta,attr" json:"isbeta,omitempty"`
	RequiresReacceptanceOfEula string `xml:"RequiresReacceptanceOfEula,attr" json:"requiresreacceptanceofeula,omitempty"`
	RecommendedCpuSpeed        string `xml:"RecommendedCpuSpeed,attr" json:"recommendedcpuspeed,omitempty"`
	RecommendedMemory          string `xml:"RecommendedMemory,attr" json:"recommendedmemory,omitempty"`
	RecommendedHardDiskSpace   string `xml:"RecommendedHardDiskSpace,attr" json:"recommendedharddiskspace,omitempty"`
	BrowseOnly                 string `xml:"BrowseOnly,attr" json:"browseonly,omitempty"`
	InstallationBehavior       struct {
		RebootBehavior      string `xml:"RebootBehavior,attr" json:"rebootbehavior,omitempty"`
		CanRequestUserInput string `xml:"CanRequestUserInput,attr" json:"canrequestuserinput,omitempty"`
	} `xml:"InstallationBehavior" json:"installationbehavior,omitempty"`
	Language []struct {
		Text string `xml:",chardata" json:"text,omitempty"`
	} `xml:"Language" json:"language,omitempty"`
	SupportUrl struct {
		Text string `xml:",chardata" json:"text,omitempty"`
	} `xml:"SupportUrl" json:"supporturl,omitempty"`
	SecurityBulletinID struct {
		Text string `xml:",chardata" json:"text,omitempty"`
	} `xml:"SecurityBulletinID" json:"securitybulletinid,omitempty"`
	KBArticleID struct {
		Text string `xml:",chardata" json:"text,omitempty"`
	} `xml:"KBArticleID" json:"kbarticleid,omitempty"`
	UninstallationBehavior struct {
		RebootBehavior string `xml:"RebootBehavior,attr" json:"rebootbehavior,omitempty"`
	} `xml:"UninstallationBehavior" json:"uninstallationbehavior,omitempty"`
	CveID []struct {
		Text string `xml:",chardata" json:"text,omitempty"`
	} `xml:"CveID" json:"cveid,omitempty"`
}

type L struct {
	Language struct {
		Text string `xml:",chardata" json:"text,omitempty"`
	} `xml:"Language" json:"language,omitempty"`
	Title struct {
		Text string `xml:",chardata" json:"text,omitempty"`
	} `xml:"Title" json:"title,omitempty"`
	Description struct {
		Text string `xml:",chardata" json:"text,omitempty"`
	} `xml:"Description" json:"description,omitempty"`
}
