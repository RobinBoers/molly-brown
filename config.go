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
	_, err := toml.DecodeFile(filename, &sysConfig)
	if err != nil {
		return sysConfig, userConfig, err
	}
	_, err = toml.DecodeFile(filename, &userConfig)
	if err != nil {
		return sysConfig, userConfig, err
	}

	// Force hostname to lowercase
	sysConfig.Hostname = strings.ToLower(sysConfig.Hostname)

	// Validate pseudo-enums
	switch userConfig.DirectorySort {
		case "Name", "Size", "Time":
		default:
			return sysConfig, userConfig, errors.New("Invalid DirectorySort value.")
	}

	// Absolutise paths
	sysConfig.DocBase, err = filepath.Abs(sysConfig.DocBase)
	if err != nil {
		return sysConfig, userConfig, err
	}
	sysConfig.CertPath, err = filepath.Abs(sysConfig.CertPath)
	if err != nil {
		return sysConfig, userConfig, err
	}
	sysConfig.KeyPath, err = filepath.Abs(sysConfig.KeyPath)
	if err != nil {
		return sysConfig, userConfig, err
	}
	if sysConfig.AccessLog != "" && sysConfig.AccessLog != "-" {
		sysConfig.AccessLog, err = filepath.Abs(sysConfig.AccessLog)
		if err != nil {
			return sysConfig, userConfig, err
		}
	}
	if sysConfig.ErrorLog != "" {
		sysConfig.ErrorLog, err = filepath.Abs(sysConfig.ErrorLog)
		if err != nil {
			return sysConfig, userConfig, err
		}
	}

	// Absolutise CGI paths
	for index, cgiPath := range sysConfig.CGIPaths {
		if !filepath.IsAbs(cgiPath) {
			sysConfig.CGIPaths[index] = filepath.Join(sysConfig.DocBase, cgiPath)
		}
	}

	// Expand CGI paths
	var cgiPaths []string
	for _, cgiPath := range sysConfig.CGIPaths {
		expandedPaths, err := filepath.Glob(cgiPath)
		if err != nil {
			return sysConfig, userConfig, errors.New("Error expanding CGI path glob " + cgiPath + ": " + err.Error())
		}
		cgiPaths = append(cgiPaths, expandedPaths...)
	}
	sysConfig.CGIPaths = cgiPaths

	// Absolutise SCGI paths
	for index, scgiPath := range sysConfig.SCGIPaths {
		sysConfig.SCGIPaths[index], err = filepath.Abs( scgiPath)
		if err != nil {
			return sysConfig, userConfig, err
		}
	}

	// Validate redirects
	for _, value := range userConfig.TempRedirects {
		if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
			return sysConfig, userConfig, errors.New("Invalid cross-protocol redirect to " + value)
		}
	}
	for _, value := range userConfig.PermRedirects {
		if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
			return sysConfig, userConfig, errors.New("Ignoring cross-protocol redirect to " + value)
		}
	}

	return sysConfig, userConfig, nil
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
		_, err = toml.DecodeFile(mollyPath, &config)
		if err != nil {
			log.Println("Error parsing .molly file " + mollyPath + ": " + err.Error())
			continue
		}

		for key, value := range config.TempRedirects {
			if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
				log.Println("Ignoring cross-protocol redirect to " + value + " in .molly file " + mollyPath)
				continue
			}
			config.TempRedirects[key] = value
		}
		for key, value := range config.PermRedirects {
			if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
				log.Println("Ignoring cross-protocol redirect to " + value + " in .molly file " + mollyPath)
				continue
			}
			config.PermRedirects[key] = value
		}

	}

	return config
}
