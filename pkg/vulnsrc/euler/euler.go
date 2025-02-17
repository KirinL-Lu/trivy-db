package euler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const eulerFormat = "EulerOS-%s"

var (
	eulerDir = "euler"

	source = types.DataSource{
		ID:   vulnerability.Euler,
		Name: "euler CVRF",
		URL:  "https://developer.huaweicloud.com/euleros/security",
	}
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	log.Println("Saving Euler CVRF")
	var cvrfs []Cvrf
	rootDir := filepath.Join(dir, "vuln-list", eulerDir)
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cvrf Cvrf
		if err := json.NewDecoder(r).Decode(&cvrf); err != nil {
			return xerrors.Errorf("failed to decode Euler CVRF JSON: %w %+v", err, cvrf)
		}
		cvrfs = append(cvrfs, cvrf)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Euler CVRF walk: %w", err)
	}

	if err = vs.save(cvrfs); err != nil {
		return xerrors.Errorf("error in Euler CVRF save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cvrfs []Cvrf) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cvrfs)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cvrfs []Cvrf) error {
	var uniqOSVers = make(map[string]struct{})
	for _, cvrf := range cvrfs {
		affectedPkgs := getAffectedPackages(cvrf.ProductTree)
		if len(affectedPkgs) == 0 {
			continue
		}

		for _, pkg := range affectedPkgs {
			advisory := types.Advisory{
				FixedVersion: pkg.FixedVersion,
				Arches:       pkg.Arches,
			}
			// Don't put the same data source multiple times.
			if _, ok := uniqOSVers[pkg.OSVer]; !ok {
				uniqOSVers[pkg.OSVer] = struct{}{}
				if err := vs.dbc.PutDataSource(tx, pkg.OSVer, source); err != nil {
					return xerrors.Errorf("failed to put data source: %w", err)
				}
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, cvrf.Tracking.ID, pkg.Name,
				[]string{pkg.OSVer}, advisory); err != nil {
				return xerrors.Errorf("unable to save %s CVRF: %w", pkg.OSVer, err)
			}
		}

		var references []string
		for _, ref := range cvrf.References {
			references = append(references, ref.URL)
		}

		severity := types.SeverityUnknown
		for _, cvuln := range cvrf.Vulnerabilities {
			for _, threat := range cvuln.Threats {
				sev := severityFromThreat(threat.Severity)
				if severity < sev {
					severity = sev
				}
			}
		}

		vuln := types.VulnerabilityDetail{
			References:  references,
			Title:       cvrf.Title,
			Description: getDetail(cvrf.Notes),
			Severity:    severity,
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cvrf.Tracking.ID, source.ID, vuln); err != nil {
			return xerrors.Errorf("failed to save Euler CVRF vulnerability: %w", err)
		}

		// for optimization
		if err := vs.dbc.PutVulnerabilityID(tx, cvrf.Tracking.ID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}
	return nil
}

func getAffectedPackages(productTree ProductTree) []Package {
	var pkgs []Package
	var osArches = make(map[string][]string) // OS version => arches
	for _, branch := range productTree.Relationship {
		// get os
		for _, changeProduct := range branch.ChangeProductions {
			for _, production := range changeProduct.Production {
				//get detail os
				osVer := getOSVersion(production.CPE)
				if osVer == "" {
					log.Printf("Unable to parse OS version: %s", production.CPE)
					continue
				}
				pkgArch := changeProduct.PackageType
				if arches, ok := osArches[osVer]; ok {
					osArches[osVer] = append(arches, changeProduct.PackageType)
				} else {
					osArches[osVer] = []string{changeProduct.PackageType}
				}
				pkgName, pkgVersion := parseProduction(production)

				if pkgName == "" || pkgVersion == "" {
					log.Printf("Unable to parse Production: %s", production)
					continue
				}
				pkg := Package{
					Name:         pkgName,
					FixedVersion: pkgVersion,
					OSVer:        osVer,
					Arches:       []string{pkgArch},
				}
				pkgs = append(pkgs, pkg)
			}
		}
	}
	return pkgs
}

func getOSVersion(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 4 || len(parts) > 5 || parts[3] != "EulerOS" {
		return ""
	}
	var version string
	if len(parts) == 5 {
		version = parts[4]
	}
	return fmt.Sprintf(eulerFormat, version)
}

func getDetail(notes []DocumentNote) string {
	for _, n := range notes {
		if n.Type == "General" {
			return n.Text
		}
	}
	return ""
}

func parseProduction(production Production) (string, string) {
	name, version := splitPkgName(production.ProductID)
	return name, version
}

func splitPkgName(product string) (string, string) {
	// Trim release
	//use ":" to split
	colonIndex := strings.LastIndex(product, ":")
	if colonIndex == -1 {
		return "", ""
	}
	afterColon := product[colonIndex+1:]

	//find last index of "-"
	dashIndex := strings.LastIndex(afterColon, "-")
	if dashIndex == -1 {
		return "", ""
	}
	//get pkg name
	namebefore := afterColon[:dashIndex]
	releasebefore := afterColon[dashIndex:]

	nameindex := strings.LastIndex(namebefore, "-")
	if nameindex == -1 {
		return "", ""
	}
	name := namebefore[:nameindex]
	version := namebefore[nameindex+1:] + releasebefore

	//get version
	lastIndex := strings.LastIndex(version, ".")
	if lastIndex == -1 {
		return "", ""
	}
	subStr := version[:lastIndex]
	if !strings.Contains(subStr, ".") {
		return name, subStr
	}
	secondLastIndex := strings.LastIndex(subStr, ".")
	if secondLastIndex == -1 {
		return "", ""
	}
	secStr := version[:secondLastIndex]
	lastStr := version[secondLastIndex+1:]

	newVersion := version
	if strings.HasSuffix(lastStr, "euleros") {
		newVersion = secStr
	} else {
		newVersion = subStr
	}

	return name, newVersion
}

func (vs VulnSrc) Get(version, pkgName, arch string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(eulerFormat, version)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Euler advisories: %w", err)
	}

	// Filter advisories by arch
	advisories = lo.Filter(advisories, func(adv types.Advisory, _ int) bool {
		return slices.Contains(adv.Arches, arch)
	})

	if len(advisories) == 0 {
		return nil, nil
	}
	return advisories, nil
}

func severityFromThreat(sev string) types.Severity {
	switch sev {
	case "Low":
		return types.SeverityLow
	case "Medium":
		return types.SeverityMedium
	case "High":
		return types.SeverityHigh
	case "Critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
