package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
)

var VERSION = "0.0.0"

func main() {
	var conf_file string
	var version bool

	// Parse args
	flag.StringVar(&conf_file, "c", "", "Path to config file")
	flag.BoolVar(&version, "v", false, "Print version and exit")
	flag.Parse()

	// If requested, print version and exit
	if version {
		fmt.Println("Molly Brown version", VERSION)
		os.Exit(0)
	}

	// Read config
	if conf_file == "" {
		_, err := os.Stat("/etc/molly.conf")
		if err == nil {
			conf_file = "/etc/molly.conf"
		}
	}
	config, err := getConfig(conf_file)
	if err != nil {
		log.Fatal(err)
	}

	// Open log files
	var errorLogFile *os.File
	if config.ErrorLog == "" {
		errorLogFile = os.Stderr
	} else {
		errorLogFile, err = os.OpenFile(config.ErrorLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer errorLogFile.Close()
	}
	errorLog := log.New(errorLogFile, "", log.Ldate | log.Ltime)

	var accessLogFile *os.File
	if config.AccessLog == "-" {
		accessLogFile = os.Stdout
	} else {
		accessLogFile, err = os.OpenFile(config.AccessLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			errorLog.Println("Error opening access log file: " + err.Error())
			log.Fatal(err)
		}
		defer accessLogFile.Close()
	}

	// Read TLS files, create TLS config
	// Check key file permissions first
	info, err := os.Stat(config.KeyPath)
	if err != nil {
		errorLog.Println("Error opening TLS key file: " + err.Error())
		log.Fatal(err)
	}
	if uint64(info.Mode().Perm())&0444 == 0444 {
		errorLog.Println("Refusing to use world-readable TLS key file " + config.KeyPath)
		os.Exit(0)
	}
	cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		errorLog.Println("Error loading TLS keypair: " + err.Error())
		log.Fatal(err)
	}
	tlscfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequestClientCert,
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(config.Port), tlscfg)
	if err != nil {
		errorLog.Println("Error creating TLS listener: " + err.Error())
		log.Fatal(err)
	}
	defer listener.Close()

	// Start log handling routines
	accessLogEntries := make(chan LogEntry, 10)
	go func() {
		for {
			entry := <-accessLogEntries
			writeLogEntry(accessLogFile, entry)
		}
	}()

	// Infinite serve loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			errorLog.Println("Error accepting connection: " + err.Error())
			log.Fatal(err)
		}
		go handleGeminiRequest(conn, config, accessLogEntries, errorLog)
	}

}
