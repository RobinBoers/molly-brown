// +build linux,go1.16 aix darwin dragonfly freebsd illumos netbsd openbsd solaris

package main

import (
	"log"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func DropPrivs(config Config, errorLog *log.Logger) {

	// Get our real and effective UIDs
	uid := os.Getuid()
	euid := os.Geteuid()

	// If these are equal and non-zero, there's nothing to do
	if uid == euid && uid != 0 {
		return
	}

	// If our real UID is root, we need to lookup the nobody UID
	if uid == 0 {
		user, err := user.Lookup("nobody")
		if err != nil {
			errorLog.Println("Could not lookup UID for user " + "nobody" + ": " + err.Error())
			log.Fatal(err)
		}
		uid, err = strconv.Atoi(user.Uid)
		if err != nil {
			errorLog.Println("Could not lookup UID fr user " + "nobody" + ": " + err.Error())
			log.Fatal(err)
		}
	}

	// Drop priveleges
	err := syscall.Setuid(uid)
	if err != nil {
		errorLog.Println("Could not setuid to " + strconv.Itoa(uid) + ": " + err.Error())
		log.Fatal(err)
	}

}
