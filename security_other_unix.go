// +build linux,go1.16 aix darwin dragonfly freebsd illumos netbsd solaris

package main

func enableSecurityRestrictions(config SysConfig, ui userInfo) error {

	// Setuid to an unprivileged user
	return DropPrivs(ui)

}
