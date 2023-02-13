// +build linux,!go1.16

package main

import (
	"log"
	"os"
)

func enableSecurityRestrictions(config Config, errorLog *log.Logger) {

	// Prior to Go 1.6, setuid did not work reliably on Linux
	// So, absolutely refuse to run as root
	uid := os.Getuid()
	euid := os.Geteuid()
	if uid == 0 || euid == 0 {
		setuid_err := "Refusing to run with root privileges when setuid() will not work!"
		errorLog.Println(setuid_err)
		log.Fatal(setuid_err)
	}
}
