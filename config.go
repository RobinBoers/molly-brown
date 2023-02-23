package main

import (
	"errors"
	"github.com/BurntSushi/toml"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Port                  int
	Hostname              string
	CertPath              string
	KeyPath               string
	DocBase               string
	HomeDocBase           string
	GeminiExt             string
	DefaultLang           string
	DefaultEncoding       string
	AccessLog             string
	ErrorLog              string
	ReadMollyFiles        bool
	TempRedirects         map[string]string
	PermRedirects         map[string]string
	MimeOverrides         map[string]string
	CGIPaths              []string
	SCGIPaths             map[string]string
	CertificateZones      map[string][]string
	AllowTLS12            bool
	DirectorySort         string
	DirectorySubdirsFirst bool
	DirectoryReverse      bool
	DirectoryTitles       bool
}

type MollyFile struct {
	GeminiExt             string
	TempRedirects         map[string]string
	PermRedirects         map[string]string
	MimeOverrides         map[string]string
	CertificateZones      map[string][]string
	DefaultLang           string
	DefaultEncoding       string
	DirectorySort         string
	DirectorySubdirsFirst bool
	DirectoryReverse      bool
	DirectoryTitles       bool
}

func getConfig(filename string) (Config, error) {

	var config Config

	// Defaults
	config.Port = 1965
	config.Hostname = "localhost"
	config.CertPath = "cert.pem"
	config.KeyPath = "key.pem"
	config.DocBase = "/var/gemini/"
	config.HomeDocBase = "users"
	config.GeminiExt = "gmi"
	config.DefaultLang = ""
	config.DefaultEncoding = ""
	config.AccessLog = "access.log"
	config.ErrorLog = ""
	config.TempRedirects = make(map[string]string)
	config.PermRedirects = make(map[string]string)
	config.CGIPaths = make([]string, 0)
	config.SCGIPaths = make(map[string]string)
	config.AllowTLS12 = true
	config.DirectorySort = "Name"
	config.DirectorySubdirsFirst = false

	// Return defaults if no filename given
	if filename == "" {
		return config, nil
	}

	// Attempt to overwrite defaults from file
	_, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return config, err
	}

	// Force hostname to lowercase
	config.Hostname = strings.ToLower(config.Hostname)

	// Validate pseudo-enums
	switch config.DirectorySort {
	case "Name", "Size", "Time":
	default:
		return config, errors.New("Invalid DirectorySort value.")
	}

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

	// Validate redirects
	for _, value := range config.TempRedirects {
		if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
			return config, errors.New("Invalid cross-protocol redirect to " + value)
		}
	}
	for _, value := range config.PermRedirects {
		if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
			return config, errors.New("Ignoring cross-protocol redirect to " + value)
		}
	}

	return config, nil
}

func parseMollyFiles(path string, config *Config) {
	// Replace config variables which use pointers with new ones,
	// so that changes made here aren't reflected everywhere.
	newTempRedirects := make(map[string]string)
	for key, value := range config.TempRedirects {
		newTempRedirects[key] = value
	}
	config.TempRedirects = newTempRedirects
	newPermRedirects := make(map[string]string)
	for key, value := range config.PermRedirects {
		newPermRedirects[key] = value
	}
	config.PermRedirects = newPermRedirects
	newMimeOverrides := make(map[string]string)
	for key, value := range config.MimeOverrides {
		newMimeOverrides[key] = value
	}
	config.MimeOverrides = newMimeOverrides
	newCertificateZones := make(map[string][]string)
	for key, value := range config.CertificateZones {
		newCertificateZones[key] = value
	}
	config.CertificateZones = newCertificateZones
	// Initialise MollyFile using main Config
	var mollyFile MollyFile
	mollyFile.GeminiExt = config.GeminiExt
	mollyFile.DefaultLang = config.DefaultLang
	mollyFile.DefaultEncoding = config.DefaultEncoding
	mollyFile.DirectorySort = config.DirectorySort
	mollyFile.DirectorySubdirsFirst = config.DirectorySubdirsFirst
	mollyFile.DirectoryReverse = config.DirectoryReverse
	mollyFile.DirectoryTitles = config.DirectoryTitles
	// Build list of directories to check
	var dirs []string
	dirs = append(dirs, path)
	for {
		if path == filepath.Clean(config.DocBase) {
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
		_, err = toml.DecodeFile(mollyPath, &mollyFile)
		if err != nil {
			log.Println("Error parsing .molly file " + mollyPath + ": " + err.Error())
			continue
		}
		// Overwrite main Config using MollyFile
		config.GeminiExt = mollyFile.GeminiExt
		config.DefaultLang = mollyFile.DefaultLang
		config.DefaultEncoding = mollyFile.DefaultEncoding
		config.DirectorySort = mollyFile.DirectorySort
		config.DirectorySubdirsFirst = mollyFile.DirectorySubdirsFirst
		config.DirectoryReverse = mollyFile.DirectoryReverse
		config.DirectoryTitles = mollyFile.DirectoryTitles
		for key, value := range mollyFile.TempRedirects {
			if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
				log.Println("Ignoring cross-protocol redirect to " + value + " in .molly file " + mollyPath)
				continue
			}
			config.TempRedirects[key] = value
		}
		for key, value := range mollyFile.PermRedirects {
			if strings.Contains(value, "://") && !strings.HasPrefix(value, "gemini://") {
				log.Println("Ignoring cross-protocol redirect to " + value + " in .molly file " + mollyPath)
				continue
			}
			config.PermRedirects[key] = value
		}
		for key, value := range mollyFile.MimeOverrides {
			config.MimeOverrides[key] = value
		}
		for key, value := range mollyFile.CertificateZones {
			config.CertificateZones[key] = value
		}
	}
}
