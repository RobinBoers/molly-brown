// +build linux,go1.16 aix darwin dragonfly freebsd illumos netbsd openbsd solaris

package main

import (
	"log"
	"os"
	"strconv"
	"syscall"
)

func DropPrivs(config Config, nobody_uid int, errorLog *log.Logger) {

	// Get our real and effective UIDs
	uid := os.Getuid()
	euid := os.Geteuid()

	// Are we root or are we running as a setuid binary?
	if uid == 0 || uid != euid {
		err := syscall.Setuid(nobody_uid)
		if err != nil {
			errorLog.Println("Could not setuid to " + strconv.Itoa(uid) + ": " + err.Error())
			log.Fatal(err)
		}
	}

}
