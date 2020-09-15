package main

import (
	"golang.org/x/sys/unix"
	"log"
)

// Restrict access to the files specified in config in an OS-dependent way.
// The OpenBSD implementation uses pledge(2) and unveil(2) to restrict the
// operations available to the molly brown executable.
func enableSecurityRestrictions(config Config, errorLog *log.Logger) {
	// Pledge to only use stdio, inet, rpath, and unveil syscalls.
	// If (S)CGI paths have been specified, also allow exec syscalls.
	// Please note that execpromises haven't been specified, meaning that
	// (S)CGI applications spawned by molly brown should pledge their own
	// restrictions.
	promises := "stdio inet rpath unveil"
	if len(config.CGIPaths) > 0 || len(config.SCGIPaths) > 0 {
		promises += " exec"
	}
	err := unix.PledgePromises(promises)
	if err != nil {
		errorLog.Println("Could not pledge: " + err.Error())
		log.Fatal(err)
	}
	// Unveil a specific list of files that we are allowed to access.
	err = unix.Unveil(config.DocBase, "r")
	if err != nil {
		errorLog.Println("Could not unveil DocBase: " + err.Error())
		log.Fatal(err)
	}
	for _, cgiPath := range config.CGIPaths {
		err = unix.Unveil(cgiPath, "rx")
		if err != nil {
			errorLog.Println("Could not unveil CGIPath: " + err.Error())
			log.Fatal(err)
		}
	}
	for _, scgiPath := range config.SCGIPaths {
		err = unix.Unveil(scgiPath, "rx")
		if err != nil {
			errorLog.Println("Could not unveil SCGIPaths: " + err.Error())
			log.Fatal(err)
		}
	}
	err = unix.UnveilBlock()
	if err != nil {
		errorLog.Println("Could not block unveil: " + err.Error())
		log.Fatal(err)
	}
}
