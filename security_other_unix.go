// +build linux,go1.16 aix darwin dragonfly freebsd illumos netbsd solaris

package main

import (
	"log"
)

func enableSecurityRestrictions(config Config, errorLog *log.Logger) {

	// Setuid to an unprivileged user
	DropPrivs(config, errorLog)
}
