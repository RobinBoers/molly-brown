package main

import (
	"errors"
	"github.com/BurntSushi/toml"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type SysConfig struct {
	Port                  int
	Hostname              string
	CertPath              string
	KeyPath               string
	AccessLog             string
	ErrorLog              string
	DocBase               string
	HomeDocBase           string
	CGIPaths              []string
	SCGIPaths             map[string]string
	ReadMollyFiles        bool
	AllowTLS12            bool
	RateLimitEnable       bool
	RateLimitAverage      int
	RateLimitBurst        int
}

type UserConfig struct {
	GeminiExt             string
	DefaultLang           string
	DefaultEncoding       string
	TempRedirects         map[string]string
	PermRedirects         map[string]string
	MimeOverrides         map[string]string
	CertificateZones      map[string][]string
	DirectorySort         string
	DirectorySubdirsFirst bool
	DirectoryReverse      bool
	DirectoryTitles       bool
}

func getConfig(filename string) (SysConfig, UserConfig, error) {

	var sysConfig SysConfig
	var userConfig UserConfig

	// Defaults
	sysConfig.Port = 1965
	sysConfig.Hostname = "localhost"
	sysConfig.CertPath = "cert.pem"
	sysConfig.KeyPath = "key.pem"
	sysConfig.AccessLog = "access.log"
	sysConfig.ErrorLog = ""
	sysConfig.DocBase = "/var/gemini/"
	sysConfig.HomeDocBase = "users"
	sysConfig.CGIPaths = make([]string, 0)
	sysConfig.SCGIPaths = make(map[string]string)
	sysConfig.ReadMollyFiles = false
	sysConfig.AllowTLS12 = true
	sysConfig.RateLimitEnable = false
	sysConfig.RateLimitAverage = 1
	sysConfig.RateLimitBurst = 10

	userConfig.GeminiExt = "gmi"
	userConfig.DefaultLang = ""
	userConfig.DefaultEncoding = ""
	userConfig.TempRedirects = make(map[string]string)
	userConfig.PermRedirects = make(map[string]string)
	userConfig.DirectorySort = "Name"
	userConfig.DirectorySubdirsFirst = false

	// Return defaults if no filename given
	if filename == "" {
		return sysConfig, userConfig, nil
	}

	// Attempt to overwrite defaults from file
	sysConfig, err := readSysConfig(filename, sysConfig)
	if err != nil {
		return sysConfig, userConfig, err
	}
	userConfig, err = readUserConfig(filename, userConfig, true)
	if err != nil {
		return sysConfig, userConfig, err
	}
	return sysConfig, userConfig, nil
}

func readSysConfig(filename string, config SysConfig) (SysConfig, error) {

	_, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return config, err
	}

	// Force hostname to lowercase
	config.Hostname = strings.ToLower(config.Hostname)

	// Absolutise paths
	config.DocBase, err = filepath.Abs(config.DocBase)
	if err != nil {
		return config, err
	}
	config.CertPath, err = filepath.Abs(config.CertPath)
	if err != nil {
		return config, err
	}
	config.KeyPath, err = filepath.Abs(config.KeyPath)
	if err != nil {
		return config, err
	}
	if config.AccessLog != "" && config.AccessLog != "-" {
		config.AccessLog, err = filepath.Abs(config.AccessLog)
		if err != nil {
			return config, err
		}
	}
	if config.ErrorLog != "" {
		config.ErrorLog, err = filepath.Abs(config.ErrorLog)
		if err != nil {
			return config, err
		}
	}

	// Absolutise CGI paths
	for index, cgiPath := range config.CGIPaths {
		if !filepath.IsAbs(cgiPath) {
			config.CGIPaths[index] = filepath.Join(config.DocBase, cgiPath)
		}
	}

	// Expand CGI paths
	var cgiPaths []string
	for _, cgiPath := range config.CGIPaths {
		expandedPaths, err := filepath.Glob(cgiPath)
		if err != nil {
			return config, errors.New("Error expanding CGI path glob " + cgiPath + ": " + err.Error())
		}
		cgiPaths = append(cgiPaths, expandedPaths...)
	}
	config.CGIPaths = cgiPaths

	// Absolutise SCGI paths
	for index, scgiPath := range config.SCGIPaths {
		config.SCGIPaths[index], err = filepath.Abs( scgiPath)
		if err != nil {
			return config, err
		}
	}

	return config, nil
}

func readUserConfig(filename string, config UserConfig, requireValid bool) (UserConfig, error) {

	_, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return config, err
	}

	// Validate pseudo-enums
	if requireValid {
		switch config.DirectorySort {
			case "Name", "Size", "Time":
			default:
				return config, errors.New("Invalid DirectorySort value.")
		}
	}

	// Validate redirects
	for key, value := range config.TempRedirects {
		if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
			if requireValid {
				return config, errors.New("Invalid cross-protocol redirect to " + value)
			} else {
				log.Println("Ignoring cross-protocol redirect to " + value + " in .molly file " + filename)
				delete(config.TempRedirects, key)
			}
		}
	}
	for key, value := range config.PermRedirects {
		if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
			if requireValid {
				return config, errors.New("Invalid cross-protocol redirect to " + value)
			} else {
				log.Println("Ignoring cross-protocol redirect to " + value + " in .molly file " + filename)
				delete(config.PermRedirects, key)
			}
		}
	}

	return config, nil
}

func parseMollyFiles(path string, docBase string, config UserConfig) UserConfig {
	// Replace config variables which use pointers with new ones,
	// so that changes made here aren't reflected everywhere.
	config.TempRedirects = make(map[string]string)
	config.PermRedirects = make(map[string]string)
	config.MimeOverrides = make(map[string]string)
	config.CertificateZones = make(map[string][]string)

	// Build list of directories to check
	var dirs []string
	dirs = append(dirs, path)
	for {
		if path == filepath.Clean(docBase) {
			break
		}
		subpath := filepath.Dir(path)
		dirs = append(dirs, subpath)
		path = subpath
	}
	// Parse files in reverse order
	for i := len(dirs) - 1; i >= 0; i-- {
		dir := dirs[i]
		// Break out of the loop if a directory doesn't exist
		_, err := os.Stat(dir)
		if os.IsNotExist(err) {
			break
		}
		// Construct path for a .molly file in this dir
		mollyPath := filepath.Join(dir, ".molly")
		_, err = os.Stat(mollyPath)
		if err != nil {
			continue
		}
		// If the file exists and we can read it, try to parse it
		config, err = readUserConfig(mollyPath, config, false)
		if err != nil {
			log.Println("Error parsing .molly file " + mollyPath + ": " + err.Error())
			continue
		}
	}

	return config
}
