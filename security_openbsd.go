package main

import (
	"golang.org/x/sys/unix"
	"log"
	"path/filepath"
)

// Restrict access to the files specified in config in an OS-dependent way.
// The OpenBSD implementation uses pledge(2) and unveil(2) to restrict the
// operations available to the molly brown executable. Please note that (S)CGI
// processes that molly brown spawns or communicates with are unrestricted
// and should pledge their own restrictions and unveil their own files.
func enableSecurityRestrictions(config Config, ui userInfo) error {

	// Setuid to an unprivileged user
	err := DropPrivs(ui)
	if err != nil {
		return err
	}

	// Unveil the configured document base as readable.
	log.Println("Unveiling \"" + config.DocBase + "\" as readable.")
	err := unix.Unveil(config.DocBase, "r")
	if err != nil {
		log.Println("Could not unveil DocBase: " + err.Error())
		return err
	}

	// Unveil cgi path globs as executable.
	for _, cgiPath := range config.CGIPaths {
		cgiGlobbedPaths, err := filepath.Glob(cgiPath)
		for _, cgiGlobbedPath := range cgiGlobbedPaths {
			log.Println("Unveiling \"" + cgiGlobbedPath + "\" as executable.")
			err = unix.Unveil(cgiGlobbedPath, "rx")
			if err != nil {
				log.Println("Could not unveil CGIPaths: " + err.Error())
				return err
			}
		}
	}

	// Unveil scgi socket paths as readable and writeable.
	for _, scgiSocket := range config.SCGIPaths {
		log.Println("Unveiling \"" + scgiSocket + "\" as read/write.")
		err = unix.Unveil(scgiSocket, "rw")
		if err != nil {
			return err
		}
	}

	// Finalize the unveil list.
	// Any files not whitelisted above won't be accessible to molly brown.
	err = unix.UnveilBlock()
	if err != nil {
		log.Println("Could not block unveil: " + err.Error())
		return err
	}

	// Pledge to only use stdio, inet, and rpath syscalls.
	promises := "stdio inet rpath"
	if len(config.CGIPaths) > 0 {
		// If CGI paths have been specified, also allow exec syscalls.
		promises += " exec proc"
	}
	if len(config.SCGIPaths) > 0 {
		// If SCGI paths have been specified, also allow unix sockets.
		promises += " unix"
	}
	err = unix.PledgePromises(promises)
	if err != nil {
		log.Println("Could not pledge: " + err.Error())
		return err
	}
}
