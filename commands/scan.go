package commands

import (
	"bufio"
	sha2562 "crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-core/artifactory/commands"
	"github.com/jfrog/jfrog-cli-core/plugins/components"
	"github.com/jfrog/jfrog-cli-core/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory/httpclient"
	clientservicesutils "github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils/checksum/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	title = `
 __  _____    ___   __   ___ _    ___    ___  ___   _   _  _ _  _ ___ ___ 
 \ \/ / _ \  /_\ \ / /  / __| |  |_ _|  / __|/ __| /_\ | \| | \| | __| _ \
  >  <|   / / _ \ V /  | (__| |__ | |   \__ \ (__ / _ \|  . |  . | _||   /
 /_/\_\_|_\/_/ \_\_|    \___|____|___|  |___/\___/_/ \_\_|\_|_|\_|___|_|_\
 v1.0                                                                         
`
	notFoundOrScanError = "Artifact doesn't exist or not indexed/cached in Xray"
)

func GetScanCommand() components.Command {
	return components.Command{
		Name:        "scan",
		Description: "Scan a package using JFrog Xray.",
		Aliases:     []string{"s"},
		Arguments:   getScanArguments(),
		Flags:       getScanFlags(),
		Action: func(c *components.Context) error {
			return scanCmd(c)
		},
	}
}

func getScanArguments() []components.Argument {
	return []components.Argument{
		{
			Name:        "path",
			Description: "The local file system path to a package which should be scanned by Xray.",
		},
	}
}

func getScanFlags() []components.Flag {
	return []components.Flag{
		components.BoolFlag{
			Name:         "security-only",
			Description:  "Provide security scan result only.",
			DefaultValue: false,
		},
		components.BoolFlag{
			Name:         "license-only",
			Description:  "Provide license scan result only.",
			DefaultValue: false,
		},
		components.StringFlag{
			Name:        "server-id",
			Description: "Artifactory server ID configured using the config command.",
		},
	}
}

type scanCommand struct {
	details         *config.ArtifactoryDetails
	path            string
	xrayUrl         string
	tgtRepo         string
	includeSecurity bool
	includeLicense  bool
}

func getRtDetails(c *components.Context) (*config.ArtifactoryDetails, error) {
	details, err := commands.GetConfig(c.GetStringFlagValue("server-id"), false)
	if err != nil {
		return nil, err
	}
	if details.Url == "" {
		return nil, errors.New("no server-id was found, or the server-id has no url")
	}
	details.Url = clientutils.AddTrailingSlashIfNeeded(details.Url)
	err = config.CreateInitialRefreshableTokensIfNeeded(details)
	if err != nil {
		return nil, err
	}
	return details, nil
}

func GetXrayScannerConfiguration() (*ConfigFile, error) {
	// Get configuration file path.
	configDir, err := GetScanConfigDir()
	if err != nil {
		return nil, err
	}
	configFilePath := filepath.Join(configDir, "config.yaml")
	exists, err := fileutils.IsFileExists(configFilePath, false)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("xray-scanner configuration does not exist")
	}
	return readXrayScannerConfiguration(configFilePath)
}

func readXrayScannerConfiguration(confFilePath string) (*ConfigFile, error) {
	// Read the template file
	content, err := fileutils.ReadFile(confFilePath)
	if err != nil {
		return nil, err
	}
	configFile := &ConfigFile{}
	err = yaml.Unmarshal(content, &configFile)
	return configFile, err
}

func scanCmd(c *components.Context) error {
	if len(c.Arguments) != 1 {
		return errors.New("Wrong number of arguments. Expected: 1, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}
	configFile, err := GetXrayScannerConfiguration()
	if err != nil {
		return err
	}
	var scanCommand = new(scanCommand)
	scanCommand.path = c.Arguments[0]
	scanCommand.xrayUrl = configFile.XrayUrl
	scanCommand.tgtRepo = configFile.TargetRepo
	details, err := getRtDetails(c)
	if err != nil {
		return err
	}
	scanCommand.details = details
	if c.GetBoolFlagValue("security-only") && c.GetBoolFlagValue("license-only") {
		return errors.New("security-only and license-only cannot be provided together. For a full scan, avoid both flags")
	}
	scanCommand.includeSecurity = !c.GetBoolFlagValue("license-only")
	scanCommand.includeLicense = !c.GetBoolFlagValue("security-only")

	return scanCommand.doScan()
}

func calcSha256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sha256 := sha2562.New()
	var multiWriter io.Writer
	pageSize := os.Getpagesize()
	sizedReader := bufio.NewReaderSize(file, pageSize)
	multiWriter = utils.AsyncMultiWriter(sha256)
	_, err = io.Copy(multiWriter, sizedReader)
	if err != nil {
		return "", err
	}
	result := fmt.Sprintf("%x", sha256.Sum(nil))
	return result, nil
}

func (cmd *scanCommand) doScan() error {
	log.Output(title)
	sha256, err := calcSha256(cmd.path)
	if err != nil {
		return err
	}
	scanResponse, err := cmd.sendSummaryRequest(sha256)
	if err != nil {
		return err
	}
	if scanErrors := scanResponse.Errors; len(scanErrors) > 0 {
		if scanErrors[0].Error == notFoundOrScanError {
			log.Output("UPLOAD AND SCAN")
		}
		return nil
	}
	printScanSummary(scanResponse, cmd)
	return nil
}

type SummaryJson struct {
	Checksums []string `json:"checksums,omitempty"`
	Paths     []string `json:"paths,omitempty"`
}
type Artifacts struct {
	Artifacts []ArtifactSummary `json:"artifacts"`
	Errors    []ArtifactError   `json:"errors,omitempty"`
}
type ArtifactSummary struct {
	General  ArtifactDetails   `json:"general"`
	Issues   []ArtifactIssue   `json:"issues"`
	Licenses []ArtifactLicense `json:"licenses"`
}
type ArtifactDetails struct {
	Name        string `json:"name,omitempty"`
	Path        string `json:"path,omitempty"`
	PkgType     string `json:"pkg_type,omitempty"`
	Sha256      string `json:"sha256,omitempty"`
	ComponentId string `json:"component_id,omitempty"`
}
type ArtifactError struct {
	Identifier string `json:"identifier"`
	Error      string `json:"error"`
}
type ArtifactIssue struct {
	Summary     string                `json:"summary,omitempty"`
	Description string                `json:"description,omitempty"`
	IssueType   string                `json:"issue_type,omitempty"`
	Severity    string                `json:"severity,omitempty"`
	Provider    string                `json:"provider,omitempty"`
	Cves        []Cve                 `json:"cves,omitempty"`
	Created     string                `json:"created,omitempty"`
	ImpactPath  []string              `json:"impact_path,omitempty"`
	Components  []VulnerableComponent `json:"components,omitempty"`
	VcsUrl      string                `json:"vcs_url,omitempty"`
	Sources     []VulSource           `json:"-"`
}
type VulSource struct {
	Name     string
	SourceId string
	Url      string
}
type Cve struct {
	Cve    string   `json:"cve,omitempty"`
	Cwe    []string `json:"cwe,omitempty"`
	CvssV2 string   `json:"cvss_v2,omitempty"`
	CvssV3 string   `json:"cvss_v3,omitempty"`
}
type Fix struct {
	Vulnerability string    `json:"vulnerability,omitempty"`
	Type          string    `json:"type,omitempty"`
	Origin        string    `json:"origin,omitempty"`
	Url           string    `json:"url,omitempty"`
	FixResolution string    `json:"fix_resolution,omitempty"`
	Date          time.Time `json:"date,omitempty"`
	Message       string    `json:"message,omitempty"`
	ExtraData     string    `json:"extra_data,omitempty"`
}
type VulnerableComponent struct {
	ComponentId   string   `json:"component_id,omitempty"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
}
type ArtifactLicense struct {
	Name        string   `json:"name,omitempty"`
	FullName    string   `json:"full_name,omitempty"`
	MoreInfoUrl []string `json:"more_info_url,omitempty"`
	Components  []string `json:"components,omitempty"`
}

func (cmd *scanCommand) sendSummaryRequest(sha256 string) (*Artifacts, error) {
	auth, err := cmd.details.CreateArtAuthConfig()
	if err != nil {
		return nil, err
	}
	client, err := httpclient.ArtifactoryClientBuilder().SetServiceDetails(&auth).Build()
	if err != nil {
		return nil, err
	}
	httpClientsDetails := auth.CreateHttpClientDetails()
	clientservicesutils.SetContentType("application/json", &httpClientsDetails.Headers)
	URL := cmd.xrayUrl + "/api/v1/summary/artifact"
	checksums := SummaryJson{Checksums: []string{sha256}}
	content, err := json.Marshal(checksums)
	resp, body, err := client.SendPost(URL, content, &httpClientsDetails)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		log.Error("Xray response: " + resp.Status + "\n" + clientutils.IndentJson(body))
	}
	artifacts := &Artifacts{}
	err = json.Unmarshal(body, artifacts)
	return artifacts, err
}

func printScanSummary(artifacts *Artifacts, c *scanCommand) {
	log.Output("Scan result for: " + c.path)
	for i, artifact := range artifacts.Artifacts {
		log.Output(strconv.Itoa(i+1) + ". " + artifact.General.Name + "\nSHA256:" + artifact.General.Sha256 + "\n")
		if c.includeLicense {
			log.Output("LICENSES (" + strconv.Itoa(len(artifact.Licenses)) + "):")
			for i, license := range artifact.Licenses {
				log.Output(strconv.Itoa(i+1) + ". " + license.Name)
			}
			log.Output()
		}
		if c.includeSecurity {
			log.Output("VULNERABILITIES (" + strconv.Itoa(len(artifact.Issues)) + "):")
			for _, vuln := range artifact.Issues {
				log.Output("Summary:" + vuln.Summary)
				log.Output("Description:" + vuln.Description)
				log.Output("Severity:" + vuln.Severity)
				log.Output("Provider:" + vuln.Provider)
				log.Output()
			}
		}
		log.Output("_______________________________________________________________\n")
	}
}
