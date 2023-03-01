package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

var VERSION = "0.0.0"

func launch(sysConfig SysConfig, userConfig UserConfig, privInfo userInfo) int {
	var err error

	// Open log files
	if sysConfig.ErrorLog != "" {
		errorLogFile, err := os.OpenFile(sysConfig.ErrorLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println("Error opening error log file: " + err.Error())
			return 1
		}
		defer errorLogFile.Close()
		log.SetOutput(errorLogFile)
	}
	log.SetFlags(log.Ldate|log.Ltime)

	var accessLogFile *os.File
	if sysConfig.AccessLog == "-" {
		accessLogFile = os.Stdout
	} else if sysConfig.AccessLog != "" {
		accessLogFile, err = os.OpenFile(sysConfig.AccessLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println("Error opening access log file: " + err.Error())
			return 1
		}
		defer accessLogFile.Close()
	}

	// Read TLS files, create TLS config
	// Check key file permissions first
	info, err := os.Stat(sysConfig.KeyPath)
	if err != nil {
		log.Println("Error opening TLS key file: " + err.Error())
		return 1
	}
	if uint64(info.Mode().Perm())&0444 == 0444 {
		log.Println("Refusing to use world-readable TLS key file " + sysConfig.KeyPath)
		return 1
	}
	// Check certificate hostname matches server hostname
	info, err = os.Stat(sysConfig.CertPath)
	if err != nil {
		log.Println("Error opening TLS certificate file: " + err.Error())
		return 1
	}
	certFile, err := os.Open(sysConfig.CertPath)
	if err != nil {
		log.Println("Error opening TLS certificate file: " + err.Error())
		return 1
	}
	certBytes, err := io.ReadAll(certFile)
	if err != nil {
		log.Println("Error reading TLS certificate file: " + err.Error())
		return 1
	}
	certDer, _ := pem.Decode(certBytes)
	if certDer == nil {
		log.Println("Error decoding TLS certificate file: " + err.Error())
		return 1
	}
	certx509, err := x509.ParseCertificate(certDer.Bytes)
	if err != nil {
		log.Println("Error parsing TLS certificate: " + err.Error())
		return 1
	}
	err = certx509.VerifyHostname(sysConfig.Hostname)
	if err != nil {
		log.Println("Invalid TLS certificate: " + err.Error())
		return 1
	}
	// Warn if certificate is expired
	now := time.Now()
	if now.After(certx509.NotAfter) {
		log.Println("Hey, your certificate expired on " + certx509.NotAfter.String() + "!!!")
	}

	// Load certificate and private key
	cert, err := tls.LoadX509KeyPair(sysConfig.CertPath, sysConfig.KeyPath)
	if err != nil {
		log.Println("Error loading TLS keypair: " + err.Error())
		return 1
	}
	var tlscfg tls.Config
	tlscfg.Certificates = []tls.Certificate{cert}
	tlscfg.ClientAuth = tls.RequestClientCert
	if sysConfig.AllowTLS12 {
		tlscfg.MinVersion = tls.VersionTLS12
	} else {
		tlscfg.MinVersion = tls.VersionTLS13
	}

	// Try to chdir to /, so we don't block any mountpoints
	// But if we can't for some reason it's no big deal
        err = os.Chdir("/")
        if err != nil {
                log.Println("Could not change working directory to /: " + err.Error())
        }

	// Apply security restrictions
	err = enableSecurityRestrictions(sysConfig, privInfo)
	if err != nil {
		log.Println("Exiting due to failure to apply security restrictions.")
		return 1
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(sysConfig.Port), &tlscfg)
	if err != nil {
		log.Println("Error creating TLS listener: " + err.Error())
		return 1
	}
	defer listener.Close()

	// Start log handling routines
	var accessLogEntries chan LogEntry
	if sysConfig.AccessLog == "" {
		accessLogEntries = nil
	} else {
		accessLogEntries = make(chan LogEntry, 10)
		go func() {
			for {
				entry := <-accessLogEntries
				writeLogEntry(accessLogFile, entry)
			}
		}()
	}

	// Start listening for signals
	shutdown := make(chan struct{})
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM)
	go func() {
		<-sigterm
		log.Println("Caught SIGTERM.  Waiting for handlers to finish...")
		close(shutdown)
		listener.Close()
	}()

	// Infinite serve loop (SIGTERM breaks out)
	running := true
	var wg sync.WaitGroup
	for running {
		conn, err := listener.Accept()
		if err == nil {
			wg.Add(1)
			go handleGeminiRequest(conn, sysConfig, userConfig, accessLogEntries, &wg)
		} else {
			select {
			case <-shutdown:
				running = false
			default:
				log.Println("Error accepting connection: " + err.Error())
			}
		}
	}
	// Wait for still-running handler Go routines to finish
	wg.Wait()
	log.Println("Exiting.")

	// Exit successfully
	return 0
}
