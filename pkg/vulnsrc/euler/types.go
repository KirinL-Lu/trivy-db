package euler

type Cvrf struct {
	Title           string           `xml:"DocumentTitle"`
	Type            string           `xml:"DocumentType"`
	Publisher       string           `xml:"DocumentPublisher,attr"`
	Tracking        DocumentTracking `xml:"DocumentTracking"`
	Notes           []DocumentNote   `xml:"DocumentNotes>Note"`
	ProductTree     ProductTree      `xml:"ProductTree"`
	References      []Reference      `xml:"DocumentReferences>Reference"`
	Vulnerabilities []Vulnerability  `xml:"Vulnerability"`
}

type DocumentTracking struct {
	ID                 string     `xml:"Identification>ID"`
	Status             string     `xml:"Status"`
	Version            string     `xml:"Version"`
	InitialReleaseDate string     `xml:"InitialReleaseDate"`
	CurrentReleaseDate string     `xml:"CurrentReleaseDate"`
	Generator          Generator  `xml:"Generator"`
	RevisionHistory    []Revision `xml:"RevisionHistory>Revision"`
}

type DocumentNote struct {
	Text    string `xml:",chardata"`
	Type    string `xml:"Type,attr"`
	Ordinal string `xml:"Ordinal,attr"`
}

type Reference struct {
	URL         string `xml:"URL"`
	Description string `xml:"Description"`
}

type ProductTree struct {
	Branches     []Branch       `xml:"Branch"`
	Relationship []Relationship `xml:"Relationship"`
}

type Relationship struct {
	ProductReference          string       `xml:"ProductReference,attr"`
	RelationType              string       `xml:"RelationType,attr"`
	RelatesToProductReference string       `xml:"RelatesToProductReference,attr"`
	Productions               []Production `xml:"FullProductName"`
	ChangeProductions         []PackageProduction
}

type PackageProduction struct {
	PackageType string       `json:"PackageType"`
	Production  []Production `json:"Production"`
}

type Branch struct {
	Type        string       `xml:"Type,attr"`
	Name        string       `xml:"Name,attr"`
	Productions []Production `xml:"FullProductName"`
}

type Production struct {
	ProductID string `xml:"ProductID,attr"`
	CPE       string `xml:"CPE,attr"`
	Text      string `xml:",chardata"`
}

type Generator struct {
	Engine string `xml:"Engine"`
	Date   string `xml:"Date"`
}

type Revision struct {
	Number      string `xml:"Number"`
	Date        string `xml:"Date"`
	Description string `xml:"Description"`
}

type Vulnerability struct {
	CVE             string      `xml:"CVE"`
	Note            string      `xml:"Notes>Note"`
	Threats         []Threat    `xml:"Threats>Threat"`
	ProductStatuses []Status    `xml:"ProductStatuses>Status"`
	CVSSScoreSets   ScoreSet    `xml:"CVSSScoreSets>ScoreSet" json:",omitempty"`
	Remediations    Remediation `xml:"Remediations>Remediation" json:",omitempty"`
}

type Threat struct {
	Type     string `xml:"Type,attr"`
	Severity string `xml:"Description"`
}

type Status struct {
	Type      string   `xml:"Type,attr"`
	ProductID []string `xml:"ProductID"`
}

type ScoreSet struct {
	BaseScore string `xml:"BaseScore" json:",omitempty"`
}

type Remediation struct {
	Type        string `xml:"Type,attr"`
	Description string `xml:"Description" json:",omitempty"`
	URL         string `xml:"URL" json:",omitempty"`
}

type Package struct {
	Name         string
	FixedVersion string
	OSVer        string
	Arches       []string
}
