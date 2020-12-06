package commands

import (
	"errors"
	commandsutils "github.com/jfrog/jfrog-cli-core/artifactory/commands/utils"
	"github.com/jfrog/jfrog-cli-core/plugins/components"
	"github.com/jfrog/jfrog-cli-core/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func GetScanConfigCommand() components.Command {
	return components.Command{
		Name:        "scanner-config",
		Description: "Generate scanner configuration.",
		Aliases:     []string{"sc"},
		Action: func(c *components.Context) error {
			return scanConfigCmd(c)
		},
	}
}

type ConfigFile struct {
	XrayUrl    string `yaml:"xrayUrl,omitempty"`
	TargetRepo string `yaml:"targetRepo,omitempty"`
}

func GetScanConfigDir() (string, error) {
	configDir, err := coreutils.GetJfrogHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "xrayScanner"), nil
}

func verifyConfigFile(configFilePath string) error {
	exists, err := fileutils.IsFileExists(configFilePath, false)
	if err != nil {
		return err
	}
	if exists {
		override := coreutils.AskYesNo("Configuration file already exists at "+configFilePath+". Override it?", false)
		if !override {
			return errors.New("operation canceled")
		}
		return nil
	}

	f, err := os.OpenFile(configFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(configFilePath)
}

func scanConfigCmd(c *components.Context) error {
	if len(c.Arguments) != 0 {
		return errors.New("Wrong number of arguments. Expected: 0, " + "Received: " + strconv.Itoa(len(c.Arguments)))
	}
	confDir, err := GetScanConfigDir()
	if err != nil {
		return err
	}
	if err = fileutils.CreateDirIfNotExist(confDir); err != nil {
		return err
	}
	configFilePath := filepath.Join(confDir, "config.yaml")
	configFile := ConfigFile{}
	if err := verifyConfigFile(configFilePath); err != nil {
		return err
	}
	configFile.XrayUrl = commandsutils.AskString("", "Jfrog Xray URL:", false, false)
	configFile.XrayUrl = strings.TrimSuffix(configFile.XrayUrl, "/")
	if coreutils.AskYesNo("Upload a file that does not exist to Artifactory?", true) {
		configFile.TargetRepo = commandsutils.AskStringWithDefault("The target repository must be selected for indexing in Xray", "Target repository:", "generic-local")
	}
	resBytes, err := yaml.Marshal(&configFile)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(configFilePath, resBytes, 0644); err != nil {
		return err
	}
	log.Info("xray-scanner config successfully created.")
	return nil
}
