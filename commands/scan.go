package commands

import (
	"bufio"
	"bytes"
	sha2562 "crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-cli-core/artifactory/commands"
	"github.com/jfrog/jfrog-cli-core/artifactory/commands/generic"
	"github.com/jfrog/jfrog-cli-core/artifactory/spec"
	utils2 "github.com/jfrog/jfrog-cli-core/artifactory/utils"
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
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	bold        = "\033[1m"
	colorGreen  = "\033[32m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[1m\033[36m"
	colorYellow = "\033[1m\033[33m"
	colorReset  = "\033[0m"
	title       = string(colorGreen) + `
 __  __                   ____ _     ___    ____                                  
 \ \/ /_ __ __ _ _   _   / ___| |   |_ _|  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
  \  /| '__/ _* | | | | | |   | |    | |   \___ \ / __/ _* | '_ \| '_ \ / _ | '__|
  /  \| | | (_| | |_| | | |___| |___ | |    ___) | (_| (_| | | | | | | |  __| |   
 /_/\_|_|  \__,_|\__, |  \____|_____|___|  |____/ \___\__,_|_| |_|_| |_|\___|_|   
                 |___/                                                          
 v1.0                                                                         
`
	notFoundOrScanError    = "Artifact doesn't exist or not indexed/cached in Xray"
	waitIntervalSeconds    = 5  // Check if the scan is completed every 5 seconds
	intervalsBeforeFailure = 24 // Wait 2 minutes at most
)

type severityType int

const (
	low severityType = iota
	medium
	high
)

var severitiesMap = map[string]severityType{
	"low":    low,
	"medium": medium,
	"high":   high,
}

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
		components.StringFlag{
			Name:         "min-severity",
			Description:  "Minimum security vulnerability severity to present: high|medium|low.",
			DefaultValue: "low",
		},
		components.BoolFlag{
			Name:         "keep",
			Description:  "Keep package in Artifactory if uploaded.",
			DefaultValue: false,
		},
	}
}

type scanCommand struct {
	details         *config.ArtifactoryDetails
	path            string
	sha256          string
	xrayUrl         string
	tgtRepo         string
	minSeverity     severityType
	includeSecurity bool
	includeLicense  bool
	deletePkg       bool
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
	scanCommand.minSeverity, err = getMinSeverity(c.GetStringFlagValue("min-severity"))
	if err != nil {
		return err
	}
	if c.GetBoolFlagValue("security-only") && c.GetBoolFlagValue("license-only") {
		return errors.New("security-only and license-only cannot be provided together. For a full scan, avoid both flags")
	}
	scanCommand.includeSecurity = !c.GetBoolFlagValue("license-only")
	scanCommand.includeLicense = !c.GetBoolFlagValue("security-only")
	sha256, err := calcSha256(scanCommand.path)
	if err != nil {
		return err
	}
	scanCommand.sha256 = sha256
	scanCommand.deletePkg = !c.GetBoolFlagValue("keep")
	printBoldString(strings.Replace(title, "*", "`", -1))
	return scanCommand.scan()
}

func getMinSeverity(minSeverityValue string) (severityType, error) {
	minSeverityKey := strings.ToLower(minSeverityValue)
	if severity, ok := severitiesMap[minSeverityKey]; ok {
		return severity, nil
	}
	return low, errors.New("illegal value for min-severity, must be one of high|medium|low")
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

func (cmd *scanCommand) scan() error {
	scanResponse, err := cmd.sendSummaryRequest()
	if err != nil {
		return err
	}
	if scanErrors := scanResponse.Errors; len(scanErrors) > 0 {
		if scanErrors[0].unsupportedErrorOccurred() {
			return errors.New("unsupported error from Xray: " + scanErrors[0].Error)
		}
		log.Output(cmd.path + " does not exist in Artifactory.")
		if cmd.tgtRepo == "" {
			return nil
		}
		log.Output("Xray-scanner will upload and scan the file.")
		if err = cmd.uploadPackage(); err != nil {
			return err
		}
		if scanResponse, err = cmd.waitFoScanToComplete(); err != nil {
			return err
		}
		if cmd.deletePkg {
			log.Debug("Xry-scanner removing the package from Artifactory")
			if err = cmd.removePackage(); err != nil {
				log.Warn("failed to delete the package: %s", err.Error())
			}
		}
	}
	printScanSummary(scanResponse, cmd)
	return nil
}

func (ae ArtifactError) unsupportedErrorOccurred() bool {
	return ae.Error != notFoundOrScanError
}

func (cmd *scanCommand) uploadPackage() error {
	uploadSpec := spec.NewBuilder().
		Pattern(cmd.path).
		Target(strings.TrimPrefix(cmd.tgtRepo, "/")).
		Flat(true).
		BuildSpec()
	uploadConfiguration := &utils2.UploadConfiguration{
		Threads:        1,
		Symlink:        false,
		ExplodeArchive: false,
		Retries:        0,
	}
	buildConfiguration := &utils2.BuildConfiguration{}
	uploadCmd := generic.NewUploadCommand()
	uploadCmd.SetUploadConfiguration(uploadConfiguration).
		SetBuildConfiguration(buildConfiguration).
		SetRtDetails(cmd.details).
		SetSpec(uploadSpec)
	if err := commands.Exec(uploadCmd); err != nil {
		return err
	}
	if uploadCmd.Result().SuccessCount() == 0 {
		return errors.New("failed to upload file to Artifactory")
	}
	return nil
}

func (cmd *scanCommand) removePackage() error {
	deleteSpec := spec.NewBuilder().
		Pattern(path.Join(cmd.tgtRepo, filepath.Base(cmd.path))).
		BuildSpec()
	deleteCommand := generic.NewDeleteCommand()
	deleteCommand.SetThreads(1).SetQuiet(true).SetRtDetails(cmd.details).SetSpec(deleteSpec)
	return commands.Exec(deleteCommand)
}

func (cmd *scanCommand) waitFoScanToComplete() (*SummaryScanResult, error) {
	log.Output("Waiting for Xray to scan the package.")
	for i := 0; i < intervalsBeforeFailure; i++ {
		time.Sleep(waitIntervalSeconds * time.Second)
		scanResponse, err := cmd.sendSummaryRequest()
		if err != nil {
			return nil, err
		}
		if scanErrors := scanResponse.Errors; len(scanErrors) > 0 {
			if scanErrors[0].unsupportedErrorOccurred() {
				return nil, errors.New("unsupported error from Xray: " + scanErrors[0].Error)
			}
			if i%4 == 0 {
				log.Output("Scanning...")
			}
			continue
		}
		return scanResponse, nil
	}
	return nil, errors.New("the scan was not completed in 2 minutes. Please try again soon")
}

func (cmd *scanCommand) sendSummaryRequest() (*SummaryScanResult, error) {
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
	checksums := SummaryJson{Checksums: []string{cmd.sha256}}
	content, err := json.Marshal(checksums)
	resp, body, err := client.SendPost(URL, content, &httpClientsDetails)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		log.Output("Xray response: " + resp.Status + "\n" + clientutils.IndentJson(body))
		return nil, errors.New("request returned with an error")
	}
	artifacts := &SummaryScanResult{}
	err = json.Unmarshal(body, artifacts)
	return artifacts, err
}

func getColoredSeverity(severity string) string {
	severity = strings.ToUpper(severity)
	switch severity {
	case "LOW":
		return string(bold+colorCyan) + severity + string(colorReset)
	case "MEDIUM":
		return string(bold+colorYellow) + severity + string(colorReset)
	case "HIGH":
		return string(bold+colorRed) + severity + string(colorReset)
	}
	return ""
}

func printBoldString(str string) {
	log.Output(bold + str + colorReset)
}

func printScanSummary(artifacts *SummaryScanResult, c *scanCommand) {
	log.Output("Scan result for: " + c.path)
	for i, artifact := range artifacts.Artifacts {
		log.Output(strconv.Itoa(i+1) + ". " + artifact.General.Name + "\nSHA256:" + artifact.General.Sha256 + "\n")
		if c.includeLicense {
			if len(artifact.Licenses) > 0 && artifact.Licenses[0].Name == "Unknown" {
				artifact.Licenses = artifact.Licenses[1:]
			}
			printBoldString("LICENSES (" + strconv.Itoa(len(artifact.Licenses)) + "):")
			for i, license := range artifact.Licenses {
				log.Output("  " + strconv.Itoa(i+1) + "." + license.Name)
			}
			log.Output()
		}

		if c.includeSecurity {
			if c.minSeverity != low {
				artifact.Issues = filterIssues(artifact.Issues, c.minSeverity)
			}
			printBoldString("VULNERABILITIES (" + strconv.Itoa(len(artifact.Issues)) + "):")
			for _, vuln := range artifact.Issues {
				if len(vuln.ImpactPath) > 0 {
					lastIndex := strings.LastIndex(vuln.ImpactPath[0], "/")
					log.Output(getColoredSeverity(vuln.Severity) + " severity [" + artifact.General.Name + " > " + vuln.ImpactPath[0][lastIndex+1:] + "] ")
					log.Output("  Location:")
					for i, loc := range vuln.ImpactPath {
						log.Output("    " + strconv.Itoa(i+1) + "." + loc)
					}
				} else {
					log.Output(getColoredSeverity(vuln.Severity) + "severity [" + artifact.General.Name + "] ")
				}

				log.Output("  Security Description:\n    " + strings.Replace(vuln.Description, ". ", ".\n    ", -1))
				if cveData := getCvePrintableData(vuln.Cves); cveData != "" {
					log.Output(strings.TrimSuffix(cveData, "\n"))
				}

				log.Output()
			}
		}
	}
}

func filterIssues(issues []ArtifactIssue, minSevirity severityType) (filteredIssues []ArtifactIssue) {
	for _, issue := range issues {
		if severity, ok := severitiesMap[strings.ToLower(issue.Severity)]; ok {
			if severity >= minSevirity {
				filteredIssues = append(filteredIssues, issue)
			}
		}
	}
	return
}

func getCvePrintableData(cves []Cve) string {
	var buffer bytes.Buffer

	if len(cves) == 0 {
		return ""
	}

	for _, cve := range cves {
		if cve.Cve != "" {
			buffer.WriteString("    CVE:" + cve.Cve + "\n")
		}
		if cve.CvssV2 != "" {
			buffer.WriteString("    CVSSv2:" + cve.CvssV2 + "\n")
		}
		if cve.CvssV3 != "" {
			buffer.WriteString("    CVSSv3:" + cve.CvssV3 + "\n")
		}
		if len(cve.Cwe) > 0 {
			buffer.WriteString("    CWE:" + strings.Join(cve.Cwe, ",") + "\n")
		}
	}
	return "  CVEs:\n" + buffer.String()
}

func getImpactPathPrintableData(impactPaths []string) string {
	var buffer bytes.Buffer
	compMap := make(map[string]bool)
	if len(impactPaths) == 0 {
		return ""
	}
	buffer.WriteString("Affected components:" + "\n")

	for _, ip := range impactPaths {
		li := strings.LastIndex(ip, "/")
		compMap[ip[li+1:]] = true
	}

	count := 1
	for comp := range compMap {
		buffer.WriteString("  " + strconv.Itoa(count) + ". " + comp + "\n")
		count++
	}
	return buffer.String()
}

type SummaryJson struct {
	Checksums []string `json:"checksums,omitempty"`
	Paths     []string `json:"paths,omitempty"`
}
type SummaryScanResult struct {
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
