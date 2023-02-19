package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
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

	// Run server and exit
	os.Exit(do_main(config))
}

func do_main(config Config) int {

	// If we are running as root, find the UID of the "nobody" user, before a
	// chroot() possibly stops seeing /etc/passwd
	privInfo, err := getUserInfo(config)
	if err != nil {
		log.Println("Exiting due to failure to apply security restrictions.")
		return 1
	}

	// Chroot, if asked
	if config.ChrootDir != "" {
		err := syscall.Chroot(config.ChrootDir)
		if err != nil {
			log.Println("Could not chroot to " + config.ChrootDir + ": " + err.Error())
			return 1
		}
	}

	// Open log files
	if config.ErrorLog != "" {
		errorLogFile, err := os.OpenFile(config.ErrorLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println("Error opening error log file: " + err.Error())
			return 1
		}
		defer errorLogFile.Close()
		log.SetOutput(errorLogFile)
	}
	log.SetFlags(log.Ldate|log.Ltime)

	var accessLogFile *os.File
	if config.AccessLog == "-" {
		accessLogFile = os.Stdout
	} else if config.AccessLog != "" {
		accessLogFile, err = os.OpenFile(config.AccessLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println("Error opening access log file: " + err.Error())
			return 1
		}
		defer accessLogFile.Close()
	}

	// Read TLS files, create TLS config
	// Check key file permissions first
	info, err := os.Stat(config.KeyPath)
	if err != nil {
		log.Println("Error opening TLS key file: " + err.Error())
		return 1
	}
	if uint64(info.Mode().Perm())&0444 == 0444 {
		log.Println("Refusing to use world-readable TLS key file " + config.KeyPath)
		return 1
	}
	cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		log.Println("Error loading TLS keypair: " + err.Error())
		return 1
	}
	var tlscfg tls.Config
	tlscfg.Certificates = []tls.Certificate{cert}
	tlscfg.MinVersion = tls.VersionTLS12
	if len(config.CertificateZones) > 0 {
		tlscfg.ClientAuth = tls.RequestClientCert
	}

	// Try to chdir to /, so we don't block any mountpoints
	// But if we can't for some reason it's no big deal
        err = os.Chdir("/")
        if err != nil {
                log.Println("Could not change working directory to /: " + err.Error())
        }

	// Apply security restrictions
	err = enableSecurityRestrictions(config, privInfo)
	if err != nil {
		log.Println("Exiting due to failure to apply security restrictions.")
		return 1
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(config.Port), &tlscfg)
	if err != nil {
		log.Println("Error creating TLS listener: " + err.Error())
		return 1
	}
	defer listener.Close()

	// Start log handling routines
	var accessLogEntries chan LogEntry
	if config.AccessLog == "" {
		accessLogEntries = nil
	} else {
		accessLogEntries := make(chan LogEntry, 10)
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
			go handleGeminiRequest(conn, config, accessLogEntries, &wg)
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
