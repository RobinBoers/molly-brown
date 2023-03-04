// +build linux,!go1.16

package main

import (
	"errors"
	"log"
	"os"
)

type userInfo struct {
}

func getUserInfo(unprivUser string) (userInfo, error) {
       var dummy userInfo
       return dummy, nil
}

func enableSecurityRestrictions(config SysConfig, ui userInfo) error {

	// Prior to Go 1.6, setuid did not work reliably on Linux
	// So, absolutely refuse to run as root
	uid := os.Getuid()
	euid := os.Geteuid()
	if uid == 0 || euid == 0 {
		setuid_err := "Refusing to run with root privileges when setuid() will not work!"
		log.Println(setuid_err)
		return errors.New(setuid_err)
	}

	return nil
}
