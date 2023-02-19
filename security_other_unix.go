// +build linux,go1.16 aix darwin dragonfly freebsd illumos netbsd solaris

package main

import (
	"log"
)

func enableSecurityRestrictions(config Config, ui userInfo, errorLog *log.Logger) error {

	// Setuid to an unprivileged user
	return DropPrivs(ui, errorLog)

}
