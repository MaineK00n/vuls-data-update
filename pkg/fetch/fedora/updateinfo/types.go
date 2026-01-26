package updateinfo

import "gopkg.in/yaml.v3"

type repomd struct {
	Revision string `xml:"revision"`
	Tags     struct {
		Content string `xml:"content"`
	} `xml:"tags"`
	Data []struct {
		Type     string `xml:"type,attr"`
		Checksum struct {
			Text string `xml:",chardata"`
			Type string `xml:"type,attr"`
		} `xml:"checksum"`
		OpenChecksum struct {
			Text string `xml:",chardata"`
			Type string `xml:"type,attr"`
		} `xml:"open-checksum"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
		Timestamp       string `xml:"timestamp"`
		Size            string `xml:"size"`
		OpenSize        string `xml:"open-size"`
		DatabaseVersion string `xml:"database_version"`
	} `xml:"data"`
}

type updateinfo struct {
	Update []Updateinfo `xml:"update"`
}

type Updateinfo struct {
	From    string `xml:"from,attr" json:"from,omitempty"`
	Status  string `xml:"status,attr" json:"status,omitempty"`
	Type    string `xml:"type,attr" json:"type,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	ID      string `xml:"id" json:"id,omitempty"`
	Title   string `xml:"title" json:"title,omitempty"`
	Issued  struct {
		Date string `xml:"date,attr" json:"date,omitempty"`
	} `xml:"issued" json:"issued,omitzero"`
	Updated struct {
		Date string `xml:"date,attr" json:"date,omitempty"`
	} `xml:"updated" json:"updated,omitzero"`
	Rights      string `xml:"rights" json:"rights,omitempty"`
	Release     string `xml:"release" json:"release,omitempty"`
	Severity    string `xml:"severity" json:"severity,omitempty"`
	Description string `xml:"description" json:"description,omitempty"`
	References  struct {
		Reference []struct {
			Text  string `xml:",chardata" json:"text,omitempty"`
			Href  string `xml:"href,attr" json:"href,omitempty"`
			ID    string `xml:"id,attr" json:"id,omitempty"`
			Type  string `xml:"type,attr" json:"type,omitempty"`
			Title string `xml:"title,attr" json:"title,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
	} `xml:"references" json:"references,omitzero"`
	Pkglist struct {
		Collection struct {
			Short    string `xml:"short,attr" json:"short,omitempty"`
			Name     string `xml:"name" json:"name,omitempty"`
			Packages []struct {
				Name     string `xml:"name,attr" json:"name,omitempty"`
				Epoch    string `xml:"epoch,attr" json:"epoch,omitempty"`
				Version  string `xml:"version,attr" json:"version,omitempty"`
				Release  string `xml:"release,attr" json:"release,omitempty"`
				Arch     string `xml:"arch,attr" json:"arch,omitempty"`
				Src      string `xml:"src,attr" json:"src,omitempty"`
				Filename string `xml:"filename" json:"filename,omitempty"`
			} `xml:"package" json:"package,omitempty"`
		} `xml:"collection" json:"collection,omitzero"`
	} `xml:"pkglist" json:"pkglist,omitzero"`
}

type modules struct {
	Document string    `yaml:"document"`
	Version  int       `yaml:"version"`
	Data     yaml.Node `yaml:"data"`
}

// https://github.com/fedora-modularity/libmodulemd/blob/f3039d851e15535955c5d80901816522f004f6dd/yaml_specs/modulemd_stream_v2.yaml
type Modulemd struct {
	Name          string                            `yaml:"name" json:"name,omitempty"`
	Stream        string                            `yaml:"stream" json:"stream,omitempty"`
	Version       int64                             `yaml:"version" json:"version,omitempty"`
	StaticContext bool                              `yaml:"static_context" json:"static_context,omitempty"`
	Context       string                            `yaml:"context" json:"context,omitempty"`
	Arch          string                            `yaml:"arch" json:"arch,omitempty"`
	Summary       string                            `yaml:"summary" json:"summary,omitempty"`
	Description   string                            `yaml:"description" json:"description,omitempty"`
	ServiceLevels map[ServiceLevelType]ServiceLevel `yaml:"servicelevels" json:"service_levels,omitempty"`
	License       struct {
		Module  []string `yaml:"module" json:"module,omitempty"`
		Content []string `yaml:"content" json:"content,omitempty"`
	} `yaml:"license" json:"license,omitzero"`
	Xmd          map[string]any `yaml:"xmd" json:"xmd,omitempty"`
	Dependencies []struct {
		BuildRequires struct {
			Platform []string `yaml:"platform" json:"platform,omitempty"`

			BuildTools []string `yaml:"buildtools" json:"build_tools,omitempty"`
			Compatible []string `yaml:"compatible" json:"compatible,omitempty"`

			Extras     []string `yaml:"extras" json:"extras,omitempty"`
			MoreExtras []string `yaml:"moreextras" json:"more_extras,omitempty"`
		} `yaml:"buildrequires" json:"build_requires,omitzero"`
		Requires struct {
			Platform []string `yaml:"platform" json:"platform,omitempty"`

			Compatible []string `yaml:"compatible" json:"compatible,omitempty"`

			Runtime []string `yaml:"runtime" json:"runtime,omitempty"`

			Extras     []string `yaml:"extras" json:"extras,omitempty"`
			MoreExtras []string `yaml:"moreextras" json:"more_extras,omitempty"`
		} `yaml:"requires" json:"requires,omitzero"`
	} `yaml:"dependencies" json:"dependencies,omitempty"`
	References struct {
		Community     string `yaml:"community" json:"community,omitempty"`
		Documentation string `yaml:"documentation" json:"documentation,omitempty"`
		Tracker       string `yaml:"tracker" json:"tracker,omitempty"`
	} `yaml:"references" json:"references,omitzero"`
	Profiles map[string]struct {
		Description string   `yaml:"description" json:"description,omitempty"`
		Rpms        []string `yaml:"rpms" json:"rpms,omitempty"`
	} `yaml:"profiles" json:"profiles,omitempty"`
	API struct {
		Rpms []string `yaml:"rpms" json:"rpms,omitempty"`
	} `yaml:"api" json:"api,omitzero"`
	Filter struct {
		Rpms []string `yaml:"rpms" json:"rpms,omitempty"`
	} `yaml:"filter" json:"filter,omitzero"`
	Demodularized struct {
		Rpms []string `yaml:"rpms" json:"rpms,omitempty"`
	} `yaml:"demodularized" json:"demodularized,omitzero"`
	Buildopts struct {
		Rpms struct {
			Macros    string   `yaml:"macros" json:"macros,omitempty"`
			Whitelist []string `yaml:"whitelist" json:"whitelist,omitempty"`
		} `yaml:"rpms" json:"rpms,omitzero"`
		Arches []string `yaml:"arches" json:"arches,omitempty"`
	} `yaml:"buildopts" json:"buildopts,omitzero"`
	Components struct {
		Rpms map[string]struct {
			Name          string   `yaml:"name" json:"name,omitempty"`
			Rationale     string   `yaml:"rationale" json:"rationale,omitempty"`
			Repository    string   `yaml:"repository" json:"repository,omitempty"`
			Cache         string   `yaml:"cache" json:"cache,omitempty"`
			Ref           string   `yaml:"ref" json:"ref,omitempty"`
			Buildonly     bool     `yaml:"buildonly" json:"buildonly,omitempty"`
			Buildroot     bool     `yaml:"buildroot" json:"buildroot,omitempty"`
			SrpmBuildroot bool     `yaml:"srpm-buildroot" json:"srpm_buildroot,omitempty"`
			Buildorder    int      `yaml:"buildorder" json:"buildorder,omitempty"`
			Arches        []string `yaml:"arches" json:"arches,omitempty"`
			Multilib      []string `yaml:"multilib" json:"multilib,omitempty"`
		} `yaml:"rpms" json:"rpms,omitempty"`
		Modules map[string]struct {
			Rationale  string `yaml:"rationale" json:"rationale,omitempty"`
			Repository string `yaml:"repository" json:"repository,omitempty"`
			Ref        string `yaml:"ref" json:"ref,omitempty"`
			Buildorder int    `yaml:"buildorder" json:"buildorder,omitempty"`
		} `yaml:"modules" json:"modules,omitempty"`
	} `yaml:"components" json:"components,omitzero"`
	Artifacts struct {
		Rpms   []string `yaml:"rpms" json:"rpms,omitempty"`
		RpmMap map[string]map[string]struct {
			Name    string  `yaml:"name" json:"name,omitempty"`
			Epoch   int     `yaml:"epoch" json:"epoch,omitempty"`
			Version float64 `yaml:"version" json:"version,omitempty"`
			Release string  `yaml:"release" json:"release,omitempty"`
			Arch    string  `yaml:"arch" json:"arch,omitempty"`
			Nevra   string  `yaml:"nevra" json:"nevra,omitempty"`
		} `yaml:"rpm-map" json:"rpm_map,omitempty"`
	} `yaml:"artifacts" json:"artifacts,omitzero"`
}

type ServiceLevelType string

const (
	ServiceLevelRawhide       ServiceLevelType = "rawhide"
	ServiceLevelStableAPI     ServiceLevelType = "stable_api"
	ServiceLevelBugFixes      ServiceLevelType = "bug_fixes"
	ServiceLevelSecurityFixes ServiceLevelType = "security_fixes"
)

type ServiceLevel struct {
	EoL string `yaml:"eol" json:"eol,omitempty"`
}
