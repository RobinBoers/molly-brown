// +build linux,go1.16 aix darwin dragonfly freebsd illumos netbsd solaris

package main

import (
	"log"
)

func enableSecurityRestrictions(config Config, nobody_uid int, errorLog *log.Logger) {

	// Setuid to an unprivileged user
	DropPrivs(config, nobody_uid, errorLog)
}
