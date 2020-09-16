package main

import (
	"golang.org/x/sys/unix"
	"log"
	"path/filepath"
)

// Restrict access to the files specified in config in an OS-dependent way.
// The OpenBSD implementation uses pledge(2) and unveil(2) to restrict the
// operations available to the molly brown executable.
func enableSecurityRestrictions(config Config, errorLog *log.Logger) {

	// Unveil a specific list of files that we are allowed to access.
	err := unix.Unveil(config.DocBase, "r")
	if err != nil {
		errorLog.Println("Could not unveil DocBase: " + err.Error())
		log.Fatal(err)
	}
	for _, cgiPath := range config.CGIPaths {
		cgiGlobbedPaths, err := filepath.Glob(cgiPath)
		for _, cgiGlobbedPath := range cgiGlobbedPaths {
			log.Println("Unveiling \"" + cgiGlobbedPath + "\" as executable.")
			err = unix.Unveil(cgiGlobbedPath, "rx")
			if err != nil {
				errorLog.Println("Could not unveil CGIPaths: " + err.Error())
				log.Fatal(err)
			}
		}
	}
	err = unix.UnveilBlock()
	if err != nil {
		errorLog.Println("Could not block unveil: " + err.Error())
		log.Fatal(err)
	}

	// Pledge to only use stdio, inet, and rpath syscalls.
	// If CGI paths have been specified, also allow exec syscalls.
	// Please note that execpromises haven't been specified, meaning that
	// CGI applications spawned by molly brown should pledge their own
	// restrictions and unveil their own files.
	promises := "stdio inet rpath"
	if len(config.CGIPaths) > 0 {
		promises += " exec proc"
	}
	err = unix.PledgePromises(promises)
	if err != nil {
		errorLog.Println("Could not pledge: " + err.Error())
		log.Fatal(err)
	}
}
